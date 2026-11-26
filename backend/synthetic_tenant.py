"""Realistic 418-Policy Regulated Financial Enterprise Synthetic Tenant Generator.

Models 'Meridian Regional Financial (Sandbox)' — a 485-endpoint, M365 E7-licensed
organization struggling with real-world Intune sprawl:
- 418 total policies (Settings Catalog, Legacy Admin Templates, Endpoint Security,
  Compliance, Update Rings, Scripts, App Configs)
- 36 Entra ID groups with 3-level nested dynamic + static inclusion/exclusion traps
- 18 tattooed on-prem AD GPO settings conflicting with Intune CSPs
- 12 recent unapproved direct portal edits (zero change control realism)
"""
from __future__ import annotations

import hashlib
from typing import Any


def _stable_id(seed: str, prefix: str = "pol") -> str:
    h = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return f"{prefix}-{h[:8]}-{h[8:12]}-{h[12:16]}"


def build_synthetic_tenant() -> dict[str, Any]:
    groups = _build_groups()
    policies = _build_policies()
    tattooed_gpos = _build_tattooed_gpos()
    unapproved_changes = _build_unapproved_changes()
    enterprise_apps = _build_enterprise_apps()
    autopilot_esp = _build_autopilot_esp_findings()
    custom_roles = _build_custom_rbac_roles()
    scope_tags = _build_scope_tag_pitfalls()
    device_personas = _build_device_persona_findings()
    devices_summary = {
        "total_managed_windows": 485,
        "by_segment": {
            "Standard Corporate / Hybrid Workstations": 226,
            "Co-Managed Active ConfigMgr + 3rd-Party Patch": 108,
            "Orphaned / Dead-Server ConfigMgr Hybrid PCs": 64,
            "Locked-Down AVD Thin-Client Kiosks (Entra Joined)": 42,
            "Hybrid AVD Multi-Session Hosts (GPO + Intune)": 28,
            "Dead-Weight Windows 10 Stragglers (EOL)": 17,
        },
        "join_state": {
            "Hybrid Entra Joined (Multi-Forest Legacy GPO)": 338,
            "Entra ID Joined (Cloud Native + AVD Kiosks)": 147,
        },
        "os_versions": {
            "Windows 11 26H2": 54,
            "Windows 11 25H2": 168,
            "Windows 11 24H2": 184,
            "Windows 11 23H2": 62,
            "Windows 10 (EOL Dead Weight)": 17,
        },
    }

    return {
        "tenant": {
            "name": "Meridian Regional Financial (Synthetic Sandbox)",
            "tenant_id": "7a4b9e10-4c22-4f88-9b31-0000sandbox0",
            "licensing": "Microsoft 365 E7 (E5 + Intune P1 + Entra Suite + Copilot + Agent 365)",
            "industry": "Regulated Financial Services (Multi-Forest M&A Sandbox)",
            "mode": "synthetic",
            "devices": devices_summary,
        },
        "groups": groups,
        "policies": policies,
        "tattooed_gpos": tattooed_gpos,
        "unapproved_changes": unapproved_changes,
        "enterprise_apps": enterprise_apps,
        "autopilot_esp": autopilot_esp,
        "custom_roles": custom_roles,
        "scope_tags": scope_tags,
        "device_personas": device_personas,
    }


def _build_groups() -> list[dict[str, Any]]:
    return [
        # Top-level dynamic & umbrella groups
        {
            "id": "grp-001",
            "name": "DYN-All-Corp-Windows11",
            "type": "Dynamic Device",
            "rule": '(device.deviceOSType -eq "Windows") -and (device.deviceOwnership -eq "Company")',
            "member_count": 485,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-002",
            "name": "SG-All-Workstations-Umbrella",
            "type": "Assigned (Nested)",
            "rule": None,
            "member_count": 472,
            "nested_children": ["grp-003", "grp-004", "grp-005", "grp-006"],
            "risk_flag": "Deep 3-level nesting — mixes Dynamic and Static groups, causing unpredictable Intune policy overlap.",
        },
        {
            "id": "grp-003",
            "name": "SG-Branch-Teller-Stations",
            "type": "Assigned (Nested)",
            "rule": None,
            "member_count": 192,
            "nested_children": ["grp-007", "grp-008", "grp-009"],
            "risk_flag": "Contains devices also targeted by DYN-All-Corp-Windows11 AND excluded by SG-Legacy-Peripheral-Exceptions.",
        },
        {
            "id": "grp-004",
            "name": "SG-CallCenter-Workstations",
            "type": "Assigned (Nested)",
            "rule": None,
            "member_count": 134,
            "nested_children": ["grp-010", "grp-011"],
            "risk_flag": "Inherits conflicting Firewall and Softphone VoIP policies via nested children.",
        },
        {
            "id": "grp-005",
            "name": "DYN-HQ-Hybrid-Joined",
            "type": "Dynamic Device",
            "rule": '(device.deviceTrustType -eq "ServerAd") -and (device.displayName -startsWith "HQ-")',
            "member_count": 118,
            "nested_children": [],
            "risk_flag": "Hybrid-joined devices still receiving tattooed AD GPOs while targeted by Intune Settings Catalog.",
        },
        {
            "id": "grp-006",
            "name": "SG-Executive-VIP-Devices",
            "type": "Assigned",
            "member_count": 16,
            "rule": None,
            "nested_children": ["grp-012"],
            "risk_flag": "Excluded from 11 security policies without documented exception expiry or RFC.",
        },
        {
            "id": "grp-007",
            "name": "DYN-Branch-North-East",
            "type": "Dynamic Device",
            "rule": '(device.displayName -startsWith "BR01-") -or (device.displayName -startsWith "BR02-")',
            "member_count": 78,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-008",
            "name": "DYN-Branch-South-West",
            "type": "Dynamic Device",
            "rule": '(device.displayName -startsWith "BR03-") -or (device.displayName -startsWith "BR04-")',
            "member_count": 74,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-009",
            "name": "SG-Branch-CheckScanner-Kiosks",
            "type": "Assigned",
            "rule": None,
            "member_count": 40,
            "nested_children": ["grp-013"],
            "risk_flag": "3rd-level nested group with conflicting BitLocker/USB/ASR exclusions.",
        },
        {
            "id": "grp-010",
            "name": "DYN-CallCenter-Remote-VDI",
            "type": "Dynamic Device",
            "rule": '(device.displayName -startsWith "CC-REM-")',
            "member_count": 82,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-011",
            "name": "SG-CallCenter-OnSite-Floor",
            "type": "Assigned",
            "rule": None,
            "member_count": 52,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-012",
            "name": "SG-VIP-NoReboot-Exceptions",
            "type": "Assigned",
            "rule": None,
            "member_count": 11,
            "nested_children": [],
            "risk_flag": "Permanent Update Ring exclusion — 11 executive laptops >45 days behind Patch Tuesday.",
        },
        {
            "id": "grp-013",
            "name": "SG-Legacy-Peripheral-Exceptions",
            "type": "Assigned",
            "rule": None,
            "member_count": 34,
            "nested_children": [],
            "risk_flag": "Nested inside SG-Branch-CheckScanner-Kiosks AND used as an Exclude group on Defender ASR — creates Include/Exclude collision.",
        },
        {
            "id": "grp-014",
            "name": "SG-IT-Endpoints-Pilot",
            "type": "Assigned",
            "rule": None,
            "member_count": 25,
            "nested_children": [],
            "risk_flag": None,
        },
        {
            "id": "grp-015",
            "name": "SG-Temp-Troubleshooting-Exclude-2023",
            "type": "Assigned",
            "rule": None,
            "member_count": 67,
            "nested_children": [],
            "risk_flag": "Stale temporary exclusion group from 2023 still bypassing BitLocker, Firewall, and Compliance on 67 endpoints!",
        },
        {
            "id": "grp-016",
            "name": "DYN-Autopilot-All-ZTDID",
            "type": "Dynamic Device",
            "rule": '(device.devicePhysicalIDs -any (_ -contains "[ZTDId]"))',
            "member_count": 144,
            "nested_children": [],
            "risk_flag": "Targeted directly by Device-based Windows Update Ring — triggers mid-OOBE ESP reboots!",
        },
        {
            "id": "grp-017",
            "name": "SG-CoreBanking-App-Users",
            "type": "Assigned User",
            "rule": None,
            "member_count": 310,
            "nested_children": ["grp-018"],
            "risk_flag": "Mixed User & Device policy targeting causes Intune assignment conflicts with DYN-All-Corp-Windows11.",
        },
        {
            "id": "grp-018",
            "name": "SG-Lending-LoanOfficers",
            "type": "Assigned User",
            "rule": None,
            "member_count": 64,
            "nested_children": [],
            "risk_flag": None,
        },
        # Clean OIB target ring groups (ready to stage)
        {"id": "grp-019", "name": "SG-Intune-OIB-Ring0-Audit", "type": "Assigned Device", "rule": None, "member_count": 25, "nested_children": [], "risk_flag": None},
        {"id": "grp-020", "name": "SG-Intune-OIB-Ring1-ITPilot", "type": "Assigned Device", "rule": None, "member_count": 58, "nested_children": [], "risk_flag": None},
        {"id": "grp-021", "name": "SG-Intune-OIB-Ring2-BranchEarly", "type": "Assigned Device", "rule": None, "member_count": 170, "nested_children": [], "risk_flag": None},
        {"id": "grp-022", "name": "SG-Intune-OIB-Ring3-BroadProd", "type": "Assigned Device", "rule": None, "member_count": 485, "nested_children": [], "risk_flag": None},
    ] + [
        {
            "id": f"grp-{i:03d}",
            "name": name,
            "type": gtype,
            "rule": rule,
            "member_count": count,
            "nested_children": children,
            "risk_flag": flag,
        }
        for i, (name, gtype, rule, count, children, flag) in enumerate(
            [
                ("DYN-Win11-23H2-Legacy", "Dynamic Device", '(device.deviceOSVersion -startsWith "10.0.22631")', 62, [], None),
                ("DYN-Win11-24H2-Standard", "Dynamic Device", '(device.deviceOSVersion -startsWith "10.0.26100")', 241, [], None),
                ("DYN-Win11-25H2-Current", "Dynamic Device", '(device.deviceOSVersion -startsWith "10.0.26200")', 182, [], None),
                ("SG-Branch05-Downtown", "Assigned Device", None, 22, [], None),
                ("SG-Branch06-Westside", "Assigned Device", None, 18, [], None),
                ("SG-VPN-AlwaysOn-Users", "Assigned User", None, 215, ["grp-018"], None),
                ("SG-Edge-Extension-Exceptions-Old", "Assigned Device", None, 44, ["grp-015"], "Nested stale exception group inheriting 67 extra devices."),
                ("SG-Defender-Exclusions-CoreApp", "Assigned Device", None, 129, ["grp-009"], "Broad exclusion scope overlaps with Branch CheckScanners."),
                ("SG-Printer-Deployment-Legacy", "Assigned Device", None, 192, [], None),
                ("SG-Compliance-Bypass-Temp", "Assigned Device", None, 29, [], "Unmonitored Compliance bypass — zero review date."),
                ("SG-WUfB-Ring-Pilot-Old", "Assigned Device", None, 31, [], "Legacy Device-targeted ring overlapping with Autopatch."),
                ("SG-WUfB-Ring-Prod-Old", "Assigned Device", None, 312, ["grp-003"], "Nested Device-targeted ring causing dual-ring conflict."),
                ("SG-Helpdesk-LAPS-Readers", "Assigned User", None, 9, [], None),
                ("SG-Intune-MAA-Approvers", "Assigned User", None, 4, [], None),
            ],
            start=23,
        )
    ]


def _build_policies() -> list[dict[str, Any]]:
    # 1. Curated high-signal policies directly tied to our 12 OIB/CIS controls & real-world sprawl
    curated: list[dict[str, Any]] = [
        # BitLocker conflicts (3 overlapping policies!)
        {
            "id": "pol-cur-001",
            "name": "WIN11 - BitLocker Encryption (2022 Legacy)",
            "category": "Endpoint Security - Disk Encryption",
            "setting_key": "bitlocker_os_xts_aes256_escrow",
            "configured_value": "AES-128 CBC + Optional Escrow",
            "assigned_include": ["DYN-All-Corp-Windows11"],
            "assigned_exclude": ["SG-Temp-Troubleshooting-Exclude-2023"],
            "last_modified": "2024-03-11",
            "modified_by": "jsmith@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Conflicts with 'SEC - BitLocker XTS-256 Silent' (AES-128 vs XTS-AES 256) and excludes 67 devices via stale 2023 troubleshooting group.",
        },
        {
            "id": "pol-cur-002",
            "name": "SEC - BitLocker XTS-256 Silent (Branch Copy)",
            "category": "Settings Catalog",
            "setting_key": "bitlocker_os_xts_aes256_escrow",
            "configured_value": "XTS-AES 256 + TPM Only",
            "assigned_include": ["SG-All-Workstations-Umbrella"],
            "assigned_exclude": ["SG-Executive-VIP-Devices"],
            "last_modified": "2026-10-19",
            "modified_by": "mchen@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Overlaps on 472 devices with 'WIN11 - BitLocker Encryption (2022 Legacy)' via nested SG-All-Workstations-Umbrella.",
        },
        # Defender ASR conflicts
        {
            "id": "pol-cur-003",
            "name": "DEF - ASR Rules Partial (2023 Test - DO NOT TOUCH)",
            "category": "Endpoint Security - Attack Surface Reduction",
            "setting_key": "defender_asr_core_rules",
            "configured_value": "3 ASR rules in Audit, 1 in Warn, 12 Not Configured",
            "assigned_include": ["SG-All-Workstations-Umbrella"],
            "assigned_exclude": ["SG-Legacy-Peripheral-Exceptions"],
            "last_modified": "2026-11-18",
            "modified_by": "dpatel@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Nested include/exclude collision: SG-All-Workstations-Umbrella nests SG-Branch-CheckScanner-Kiosks which nests SG-Legacy-Peripheral-Exceptions.",
        },
        {
            "id": "pol-cur-004",
            "name": "DEF - Defender AV Exclusions (Core Banking Temp)",
            "category": "Endpoint Security - Antivirus",
            "setting_key": "defender_asr_core_rules",
            "configured_value": "Broad C:\\CoreApp\\* + *.exe folder exclusions",
            "assigned_include": ["SG-Defender-Exclusions-CoreApp", "DYN-All-Corp-Windows11"],
            "assigned_exclude": [],
            "last_modified": "2026-11-21",
            "modified_by": "helpdesk-tier2@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "unapproved_change",
            "conflict_reason": "Unapproved portal edit broadened folder exclusions to ALL corporate laptops instead of branch kiosks.",
        },
        # LAPS
        {
            "id": "pol-cur-005",
            "name": "IDN - Windows LAPS Pilot (Unfinished)",
            "category": "Endpoint Security - Account Protection",
            "setting_key": "windows_laps_entra_rotation",
            "configured_value": "Entra ID Backup (Pilot Only — 25 devices)",
            "assigned_include": ["SG-IT-Endpoints-Pilot"],
            "assigned_exclude": [],
            "last_modified": "2025-08-04",
            "modified_by": "admin-svc@meridianfin.local",
            "rfc_tag": "CHG-004118",
            "status_flag": "partial",
            "conflict_reason": "Only deployed to 25 IT devices; remaining 460 endpoints still rely on legacy on-prem AdmPwd.dll GPO.",
        },
        # Credential Guard
        {
            "id": "pol-cur-006",
            "name": "SEC - VBS & HVCI Test Profile (Orphaned)",
            "category": "Settings Catalog",
            "setting_key": "credential_guard_hvci_enabled",
            "configured_value": "Credential Guard UEFI Lock = Enabled",
            "assigned_include": [],
            "assigned_exclude": [],
            "last_modified": "2025-02-14",
            "modified_by": "former-consultant@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "orphaned",
            "conflict_reason": "Unassigned orphaned policy left behind with risky UEFI Lock enabled (no remote rollback if accidentally assigned).",
        },
        # Firewall conflicts
        {
            "id": "pol-cur-007",
            "name": "NET - Windows Firewall Baseline (Strict Copy)",
            "category": "Endpoint Security - Firewall",
            "setting_key": "windows_firewall_all_profiles",
            "configured_value": "Public On, AllowLocalPolicyMerge = False",
            "assigned_include": ["SG-CallCenter-Workstations"],
            "assigned_exclude": ["SG-Temp-Troubleshooting-Exclude-2023"],
            "last_modified": "2026-11-12",
            "modified_by": "netops@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Strict AllowLocalPolicyMerge=False triggered VoIP softphone drops; collides with legacy Firewall Admin Template.",
        },
        {
            "id": "pol-cur-008",
            "name": "LEGACY - Admin Template Firewall Disable Domain Profile",
            "category": "Administrative Templates (Legacy)",
            "setting_key": "windows_firewall_all_profiles",
            "configured_value": "Domain Profile Firewall = Disabled",
            "assigned_include": ["DYN-HQ-Hybrid-Joined", "SG-Branch-Teller-Stations"],
            "assigned_exclude": [],
            "last_modified": "2023-09-29",
            "modified_by": "jsmith@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Directly disables Domain Firewall on 310 devices to work around an old 2023 printer spooler ticket.",
        },
        # UAC
        {
            "id": "pol-cur-009",
            "name": "SEC - Local Admin & UAC Relaxed (Teller Workaround)",
            "category": "Settings Catalog",
            "setting_key": "uac_secure_desktop_standard_user",
            "configured_value": "PromptOnSecureDesktop = 0 (Disabled)",
            "assigned_include": ["SG-Branch-Teller-Stations"],
            "assigned_exclude": [],
            "last_modified": "2026-11-15",
            "modified_by": "helpdesk-tier2@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "unapproved_change",
            "conflict_reason": "Secure Desktop disabled without RFC so remote support tool didn't show black screen; violates CIS 2.3.17.3.",
        },
        # Windows Update / Autopilot Traps
        {
            "id": "pol-cur-010",
            "name": "UPD - Windows Update Ring - Corporate All (Device Targeted)",
            "category": "Windows Update Rings",
            "setting_key": "wufb_patching_rings_oobe_safe",
            "configured_value": "Quality Deferral 14d, Targeted to Device Group DYN-Autopilot-All-ZTDID",
            "assigned_include": ["DYN-Autopilot-All-ZTDID", "SG-WUfB-Ring-Prod-Old"],
            "assigned_exclude": ["SG-VIP-NoReboot-Exceptions"],
            "last_modified": "2026-10-28",
            "modified_by": "mchen@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Device-targeted ring hits Autopilot ESP devices (causing mid-OOBE coalesced reboots) and overlaps with SG-WUfB-Ring-Pilot-Old.",
        },
        {
            "id": "pol-cur-011",
            "name": "UPD - Feature Update Win11 25H2 (ASAP Rollout Trap)",
            "category": "Windows Feature Updates",
            "setting_key": "wufb_patching_rings_oobe_safe",
            "configured_value": "Rollout = Make Available As Soon As Possible",
            "assigned_include": ["DYN-All-Corp-Windows11"],
            "assigned_exclude": ["SG-VIP-NoReboot-Exceptions"],
            "last_modified": "2026-11-20",
            "modified_by": "mchen@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "unapproved_change",
            "conflict_reason": "'Make Available ASAP' silently bypasses Update Ring deferrals and forces immediate 25H2 upgrades across branches.",
        },
        # Device Compliance
        {
            "id": "pol-cur-012",
            "name": "CMP - Windows 11 Basic Compliance (Permissive)",
            "category": "Device Compliance",
            "setting_key": "device_compliance_zero_trust_ca",
            "configured_value": "Require BitLocker = Not Configured, Min OS = 10.0.19041 (Win10)",
            "assigned_include": ["DYN-All-Corp-Windows11"],
            "assigned_exclude": ["SG-Compliance-Bypass-Temp", "SG-Temp-Troubleshooting-Exclude-2023"],
            "last_modified": "2024-06-18",
            "modified_by": "jsmith@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "96 devices excluded via stale bypass groups; Min OS still allows EOL Windows 10 and BitLocker is not enforced.",
        },
        # Edge Baseline
        {
            "id": "pol-cur-013",
            "name": "BRW - Edge Settings (Copy of Copy - 2024)",
            "category": "Settings Catalog",
            "setting_key": "edge_security_baseline_extensions",
            "configured_value": "SmartScreen = User Overridable, Extension Control = Not Configured",
            "assigned_include": ["SG-CoreBanking-App-Users"],
            "assigned_exclude": ["SG-Edge-Extension-Exceptions-Old"],
            "last_modified": "2026-11-09",
            "modified_by": "dpatel@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Users can click through SmartScreen phishing warnings; nested exclusion group silently exempts 111 devices.",
        },
        # USB / Removable Media
        {
            "id": "pol-cur-014",
            "name": "DLP - Removable Storage Policy (Disabled After Branch Incident)",
            "category": "Endpoint Security - Attack Surface Reduction",
            "setting_key": "removable_usb_write_control",
            "configured_value": "RDVDenyWriteAccess = Not Configured (Unassigned after scanner outage)",
            "assigned_include": [],
            "assigned_exclude": [],
            "last_modified": "2026-07-03",
            "modified_by": "helpdesk-tier2@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "orphaned",
            "conflict_reason": "Previously pulled after blanket USB block broke branch check scanners; zero write-protection currently active on member PII.",
        },
        # MAA
        {
            "id": "pol-cur-015",
            "name": "GOV - Multi-Admin Approval Status",
            "category": "Tenant Administration",
            "setting_key": "intune_maa_dual_control",
            "configured_value": "Disabled across all workloads (0 MAA policies active)",
            "assigned_include": [],
            "assigned_exclude": [],
            "last_modified": "2026-01-01",
            "modified_by": "system",
            "rfc_tag": None,
            "status_flag": "missing",
            "conflict_reason": "Any single Intune Admin can wipe all 485 devices or push arbitrary PowerShell scripts without dual control.",
        },
        # Agent 365 / MCP Governance
        {
            "id": "pol-cur-016",
            "name": "GOV - Legacy Intune Automation App (Client Secret + Broad RW)",
            "category": "Entra Workload Identity",
            "setting_key": "agent365_mcp_governance_gate",
            "configured_value": "24-month Client Secret + DeviceManagementConfiguration.ReadWrite.All (Unmonitored)",
            "assigned_include": ["Tenant-Wide"],
            "assigned_exclude": [],
            "last_modified": "2025-11-30",
            "modified_by": "admin-svc@meridianfin.local",
            "rfc_tag": None,
            "status_flag": "conflict",
            "conflict_reason": "Static client secret with unrestricted Graph write scope and zero ITIL RFC gating; fails InfoSec/ARB review.",
        },
    ]

    # 2. Programmatically generate 402 realistic enterprise sprawl policies (total = 418 policies!)
    # Mirrors real credit-union / mid-market tenants with years of ad-hoc Settings Catalog,
    # legacy Admin Templates, branch Wi-Fi/Printer/App configs, duplicates, and orphans.
    templates = [
        ("Settings Catalog", "SC - Edge Homepage & Bookmarks - {dept} v{v}", "edge_bookmarks", "Configured"),
        ("Settings Catalog", "SC - OneDrive Known Folder Move - {dept} ({yr})", "onedrive_kfm", "Silent Move + Prompt"),
        ("Settings Catalog", "SC - Power & Sleep Timeout - {dept}", "power_sleep", "15 min lock / 30 min sleep"),
        ("Settings Catalog", "SC - Windows Hello for Business - {dept}", "whfb_pin", "PIN 6 digits"),
        ("Administrative Templates (Legacy)", "LEGACY GPO Import - Office {yr} Macro & Trust - {dept}", "office_macros", "Mixed Legacy"),
        ("Administrative Templates (Legacy)", "LEGACY GPO Import - IE Mode CoreBanking SiteList - {dept}", "edge_iemode", "SiteList XML v{v}"),
        ("Endpoint Security - Antivirus", "AV - Scheduled Quick Scan & Cloud Block - {dept}", "defender_av", "Daily 12:00 PM"),
        ("Endpoint Security - Firewall", "FW - Allow Inbound Port Rule - {dept} App #{v}", "fw_app_rule", "TCP Allow"),
        ("Device Configuration (Custom OMA-URI)", "OMA-URI - Legacy Printer / Scanner Registry Fix - {dept}", "custom_oma", "Custom SyncML"),
        ("PowerShell Platform Scripts", "PS1 - Map Network Drive / Shortcut - {dept} ({yr})", "ps_drive_map", "Run as User"),
        ("Proactive Remediations", "REM - Clear Browser Cache / Teams Reset - {dept}", "rem_cleanup", "Weekly Schedule"),
        ("Windows Update Rings", "UPD - Legacy Dept Ring Copy - {dept} ({yr})", "wufb_legacy", "Defer 10d"),
        ("App Configuration Policies", "APP - Outlook / Teams / Edge Mobile Config - {dept}", "app_cfg", "Managed Devices"),
        ("Device Compliance", "CMP - Departmental Compliance Clone - {dept}", "cmp_clone", "Basic Rules"),
    ]
    depts = [
        "Branch01-North", "Branch02-East", "Branch03-South", "Branch04-West",
        "Branch05-Downtown", "Branch06-Westside", "CallCenter-Tier1", "CallCenter-Escalations",
        "Lending-Mortgage", "Lending-Auto", "MemberServices", "Compliance-Audit",
        "Finance-Accounting", "HR-Recruiting", "Marketing-Digital", "IT-Helpdesk",
        "IT-Infrastructure", "Exec-Leadership", "Kiosk-Lobby", "Remote-Contractors",
        "CoreBanking-Teller", "Treasury-Ops", "Fraud-Risk", "Collections",
        "Facilities", "Training-Lab", "Loan-Processing", "Card-Services", "Board-Tablets",
    ]
    groups_pool = [
        "DYN-All-Corp-Windows11",
        "SG-All-Workstations-Umbrella",
        "SG-Branch-Teller-Stations",
        "SG-CallCenter-Workstations",
        "DYN-HQ-Hybrid-Joined",
        "SG-CoreBanking-App-Users",
        "DYN-Branch-North-East",
        "DYN-Branch-South-West",
        "SG-Executive-VIP-Devices",
        "SG-IT-Endpoints-Pilot",
    ]
    admins = [
        "jsmith@meridianfin.local",
        "mchen@meridianfin.local",
        "dpatel@meridianfin.local",
        "helpdesk-tier2@meridianfin.local",
        "former-consultant@meridianfin.local",
        "admin-svc@meridianfin.local",
    ]

    generated: list[dict[str, Any]] = []
    target_generated = 402
    idx = 0
    while len(generated) < target_generated:
        t_cat, t_name, t_key, t_val = templates[idx % len(templates)]
        dept = depts[(idx * 7 + idx // len(templates)) % len(depts)]
        yr = 2022 + (idx % 5)
        v = 1 + (idx % 4)
        name = t_name.format(dept=dept, yr=yr, v=v)
        if idx % 17 == 0:
            name = f"COPY OF {name} - TEST"
        elif idx % 29 == 0:
            name = f"[OLD DO NOT USE] {name}"

        # Realistic distribution of sprawl flags
        if idx % 19 == 0:
            status_flag = "orphaned"
            inc = []
            exc = []
            reason = "Unassigned policy contributing to console clutter; no change ticket."
        elif idx % 11 == 0:
            status_flag = "duplicate"
            inc = [groups_pool[idx % len(groups_pool)], groups_pool[(idx + 1) % len(groups_pool)]]
            exc = ["SG-Temp-Troubleshooting-Exclude-2023"] if idx % 22 == 0 else []
            reason = "Duplicates settings already defined in global Settings Catalog; creates overlapping MDM evaluation."
        elif idx % 13 == 0:
            status_flag = "conflict"
            inc = ["SG-All-Workstations-Umbrella", groups_pool[idx % len(groups_pool)]]
            exc = ["SG-Legacy-Peripheral-Exceptions"] if idx % 26 == 0 else []
            reason = "Nested group assignment overlaps with legacy Administrative Template or parallel Settings Catalog profile."
        elif idx % 41 == 0:
            status_flag = "unapproved_change"
            inc = [groups_pool[idx % len(groups_pool)]]
            exc = []
            reason = "Modified directly in Intune portal within last 14 days with zero ITIL RFC reference."
        else:
            status_flag = "healthy"
            inc = [groups_pool[idx % len(groups_pool)]]
            exc = []
            reason = ""

        month = 1 + (idx % 11)
        day = 1 + (idx % 27)
        last_mod = f"2026-{month:02d}-{day:02d}" if status_flag == "unapproved_change" else f"{yr}-{month:02d}-{day:02d}"

        generated.append(
            {
                "id": _stable_id(f"{idx}-{name}", "pol"),
                "name": name,
                "category": t_cat,
                "setting_key": t_key,
                "configured_value": t_val.format(v=v),
                "assigned_include": inc,
                "assigned_exclude": exc,
                "last_modified": last_mod,
                "modified_by": admins[idx % len(admins)],
                "rfc_tag": f"CHG-00{4100 + idx}" if (idx % 15 == 0 and status_flag == "healthy") else None,
                "status_flag": status_flag,
                "conflict_reason": reason,
            }
        )
        idx += 1

    return curated + generated


def _build_tattooed_gpos() -> list[dict[str, Any]]:
    return [
        {
            "gpo_name": "GPO-WSUS-Internal-Patching-2019",
            "setting_key": "wufb_patching_rings_oobe_safe",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer=1",
            "impact": "Blocks Windows Update for Business / Autopatch cloud scans on 368 Hybrid-joined devices.",
            "severity": "Critical",
        },
        {
            "gpo_name": "GPO-BitLocker-AES128-ADBackup",
            "setting_key": "bitlocker_os_xts_aes256_escrow",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft\FVE\EncryptionMethodWithXtsOs=3 (AES-128)",
            "impact": "Overrides Intune XTS-AES 256 Disk Encryption policy and escrows keys only to on-prem AD.",
            "severity": "High",
        },
        {
            "gpo_name": "GPO-Legacy-LAPS-AdmPwd",
            "setting_key": "windows_laps_entra_rotation",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled=1",
            "impact": "Legacy AdmPwd.dll CSE fights native Windows LAPS Entra ID password rotation.",
            "severity": "High",
        },
        {
            "gpo_name": "GPO-Domain-Firewall-Off-Printers",
            "setting_key": "windows_firewall_all_profiles",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall=0",
            "impact": "Tattooed registry value keeps Domain Firewall disabled even after Intune profile applies.",
            "severity": "Critical",
        },
        {
            "gpo_name": "GPO-Defender-Legacy-AV-Disable",
            "setting_key": "defender_asr_core_rules",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring=1",
            "impact": "Leftover from 2021 third-party AV migration; suppresses Defender RTP on 42 branch PCs.",
            "severity": "Critical",
        },
        {
            "gpo_name": "GPO-Edge-AllowAllExtensions",
            "setting_key": "edge_security_baseline_extensions",
            "registry_path": r"HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist=*",
            "impact": "Wildcard extension allowlist overrides Intune Edge security baseline.",
            "severity": "Medium",
        },
        {
            "gpo_name": "GPO-UAC-NoSecureDesktop-Helpdesk",
            "setting_key": "uac_secure_desktop_standard_user",
            "registry_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=0",
            "impact": "Exposes UAC elevation prompts to UI spoofing / privilege escalation attacks.",
            "severity": "High",
        },
        {
            "gpo_name": "GPO-USB-AllowAll-BranchScanners",
            "setting_key": "removable_usb_write_control",
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess=0",
            "impact": "Explicitly permits unencrypted USB mass-storage writes on teller machines.",
            "severity": "High",
        },
    ] + [
        {
            "gpo_name": f"GPO-Legacy-Baseline-Fragment-{i:02d}",
            "setting_key": "legacy_misc",
            "registry_path": rf"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\LegacyFlag{i}=1",
            "impact": "Unmapped legacy domain GPO fragment creating MDM winning-provider ambiguity.",
            "severity": "Low",
        }
        for i in range(1, 11)
    ]


def _build_unapproved_changes() -> list[dict[str, Any]]:
    return [
        {
            "timestamp_utc": "2026-11-23T19:42:10Z",
            "actor": "helpdesk-tier2@meridianfin.local",
            "policy_name": "DEF - Defender AV Exclusions (Core Banking Temp)",
            "change_summary": "Added 'DYN-All-Corp-Windows11' to Include assignments for broad C:\\CoreApp\\* exclusion",
            "rfc_ticket": None,
            "severity": "Critical",
        },
        {
            "timestamp_utc": "2026-11-22T15:18:44Z",
            "actor": "mchen@meridianfin.local",
            "policy_name": "UPD - Feature Update Win11 25H2 (ASAP Rollout Trap)",
            "change_summary": "Changed rollout option from Gradual Rollout to 'Make Available As Soon As Possible'",
            "rfc_ticket": None,
            "severity": "High",
        },
        {
            "timestamp_utc": "2026-11-21T11:05:22Z",
            "actor": "dpatel@meridianfin.local",
            "policy_name": "DEF - ASR Rules Partial (2023 Test - DO NOT TOUCH)",
            "change_summary": "Switched 'Block Adobe Reader child processes' from Block to Off after single ticket",
            "rfc_ticket": None,
            "severity": "High",
        },
        {
            "timestamp_utc": "2026-11-19T22:14:03Z",
            "actor": "helpdesk-tier2@meridianfin.local",
            "policy_name": "SEC - Local Admin & UAC Relaxed (Teller Workaround)",
            "change_summary": "Disabled PromptOnSecureDesktop on SG-Branch-Teller-Stations (192 endpoints)",
            "rfc_ticket": None,
            "severity": "High",
        },
        {
            "timestamp_utc": "2026-11-18T16:51:09Z",
            "actor": "netops@meridianfin.local",
            "policy_name": "NET - Windows Firewall Baseline (Strict Copy)",
            "change_summary": "Added SG-Temp-Troubleshooting-Exclude-2023 to Firewall exclusions",
            "rfc_ticket": None,
            "severity": "Medium",
        },
        {
            "timestamp_utc": "2026-11-16T09:30:00Z",
            "actor": "mchen@meridianfin.local",
            "policy_name": "SG-Compliance-Bypass-Temp",
            "change_summary": "Added 7 executive & lending laptops to Device Compliance exclusion group",
            "rfc_ticket": None,
            "severity": "High",
        },
    ]


def _build_enterprise_apps() -> list[dict[str, Any]]:
    return [
        {
            "app_name": "Legacy-Intune-Sync-Script",
            "app_id": "a1102f44-89be-4c11-9012-000000000001",
            "auth_type": "Client Secret (24-month, expires 2027-11)",
            "graph_permissions": ["DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementManagedDevices.ReadWrite.All"],
            "maa_break_risk": "HIGH — Will fail with HTTP 400/403 once Multi-Admin Approval is enabled unless excluded or refactored.",
        },
        {
            "app_name": "ThirdParty-Patch-Publisher",
            "app_id": "b2209d11-12ab-4e33-8821-000000000002",
            "auth_type": "Certificate (X.509)",
            "graph_permissions": ["DeviceManagementApps.ReadWrite.All"],
            "maa_break_risk": "HIGH — Requires explicit Intune MAA Enterprise Application exclusion before protecting Apps.",
        },
        {
            "app_name": "IntuneGuard-Studio-AuditReader",
            "app_id": "c3301e99-77cd-4a55-9100-000000000003",
            "auth_type": "Managed Identity / Workload Identity Federation",
            "graph_permissions": ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All", "Group.Read.All", "AuditLog.Read.All"],
            "maa_break_risk": "SAFE — Read-only GET requests are never blocked by MAA.",
        },
    ]


def _build_autopilot_esp_findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "AP-001",
            "object_name": "ESP - Corporate Standard (Default)",
            "object_type": "Enrollment Status Page (ESP)",
            "severity": "Critical",
            "finding": "Blocks enrollment on 18 mixed Win32 + LOB (.msi) apps with a 20-minute timeout AND 'Install Windows Updates during OOBE' = Yes.",
            "why_it_breaks": "Mixing Win32 and LOB apps during ESP causes MSI installer mutex collisions (0x80070652), while OOBE quality updates exhaust the 20-minute timeout and fail Autopilot with 0x81036502.",
            "recommended_fix": "Wrap all LOB MSIs as Win32 (.intunewin), limit blocking ESP apps to 4 core apps (Defender/VPN/M365/Company Portal), set timeout to 60 min, and enable log collection.",
        },
        {
            "id": "AP-002",
            "object_name": "AP - Branch Workstations (User-Driven Hybrid)",
            "object_type": "Autopilot Deployment Profile",
            "severity": "High",
            "finding": "Still configured for Hybrid Entra Join with 'Skip AD connectivity check = No' + user account type set to Administrator.",
            "why_it_breaks": "Remote/branch deployments fail whenever line-of-sight to an on-prem DC lags, and granting Local Admin during OOBE violates NCUA/CIS least privilege.",
            "recommended_fix": "Switch new Autopilot deployments to Cloud-Native Entra ID Join + Standard User + Cloud Kerberos Trust for on-prem file/print shares.",
        },
        {
            "id": "AP-003",
            "object_name": "UPD - Windows Update Ring - Corporate All",
            "object_type": "Windows Update Ring",
            "severity": "Critical",
            "finding": "Assigned directly to Device group 'DYN-Autopilot-All-ZTDID' + paired with Feature Update '25H2 ASAP'.",
            "why_it_breaks": "Device-targeted update rings apply during Device ESP and trigger unexpected mid-OOBE reboots/double logins; 'ASAP' Feature Update silently bypasses your 14-day Update Ring deferral.",
            "recommended_fix": "Target Update Rings to flat User/Post-OOBE groups, switch Feature Update to Gradual Rollout, and deploy Remediate-WUfB-StaleWSUSLocks.",
        },
    ]


def _build_custom_rbac_roles() -> list[dict[str, Any]]:
    return [
        {
            "id": "RBAC-001",
            "role_name": "Custom - Helpdesk Tier 1 & Branch Support",
            "members_count": 14,
            "severity": "Critical",
            "overprivileged_permissions": [
                "Managed Devices: Wipe = Yes",
                "Managed Devices: Delete = Yes",
                "Device Configurations: Assign = Yes",
                "Remote Tasks: Run Scripts = Yes",
            ],
            "why_it_is_dangerous": "14 Tier-1 helpdesk accounts can wipe all 485 workstations or push arbitrary SYSTEM PowerShell scripts with zero Multi-Admin Approval.",
            "recommended_fix": "Remove Wipe/Delete/Assign/Script rights from Tier 1 (keep Sync, Restart, LAPS Read, BitLocker Key Read) and require MAA for Tier 2+ destructive actions.",
        },
        {
            "id": "RBAC-002",
            "role_name": "Custom - Application Packager (Legacy)",
            "members_count": 6,
            "severity": "High",
            "overprivileged_permissions": [
                "Device Compliance Policies: Update = Yes",
                "Endpoint Security Policies: Update = Yes",
                "Role Assignments: Read/Write = Yes",
            ],
            "why_it_is_dangerous": "App packagers were cloned from a broad role and can silently edit Defender ASR, Compliance policies, or escalate their own RBAC permissions.",
            "recommended_fix": "Rebuild from built-in 'Application Manager' template with strictly Mobile Apps Create/Update + Scope Tag restricted to non-production Pilot ring.",
        },
        {
            "id": "RBAC-003",
            "role_name": "Built-In Intune Administrator (Standing Direct Assignment)",
            "members_count": 9,
            "severity": "High",
            "overprivileged_permissions": ["Full Standing Intune Admin (No Entra PIM JIT Elevation)"],
            "why_it_is_dangerous": "9 accounts hold permanent 24/7 Intune Administrator rights instead of time-bound Entra PIM elevation (included in M365 E7 / Entra P2).",
            "recommended_fix": "Convert all 9 to Eligible in Entra PIM (4-hour max activation, MFA + ticket justification required), keeping only 2 cloud break-glass accounts.",
        },
    ]


def _build_scope_tag_pitfalls() -> list[dict[str, Any]]:
    return [
        {
            "id": "TAG-001",
            "object_name": "34 Policies Tagged 'Branch-Ops-Only' (Missing 'Default' Scope Tag)",
            "scope_tags_applied": ["Branch-Ops-Only"],
            "severity": "High",
            "pitfall": "An engineer removed the 'Default' Scope Tag from 34 branch policies. Now Security Auditors and HQ Admins (scoped to Default) literally cannot see those 34 policies in the Intune portal!",
            "real_world_symptom": "Admins create duplicate policies because they think the setting isn't configured—directly fueling 400-policy sprawl and mystery conflicts.",
            "recommended_fix": "Keep the 'Default' Scope Tag on shared/global policies OR grant Read-Only Auditors visibility across All Scope Tags; document a strict 3-tag max naming standard.",
        },
        {
            "id": "TAG-002",
            "object_name": "62 Branch Devices Missing Auto-Assigned Scope Tag",
            "scope_tags_applied": ["Default only"],
            "severity": "Medium",
            "pitfall": "Regional Branch Support role is scoped exclusively to tag 'Region-West', but 62 newly Autopilot-enrolled laptops were never assigned 'Region-West' via dynamic group.",
            "real_world_symptom": "Branch technicians open Intune to retrieve a BitLocker key or LAPS password and see 'Device not found' during live member-facing outages.",
            "recommended_fix": "Assign Scope Tags strictly via clean flat Dynamic Device groups (e.g., DYN-Branch-West) and verify Scope Tag coverage weekly.",
        },
        {
            "id": "TAG-003",
            "object_name": "Scope Tag Misused as Targeting Mechanism (8 Policies)",
            "scope_tags_applied": ["Exec-VIP-Tag"],
            "severity": "Medium",
            "pitfall": "A former admin thought applying 'Exec-VIP-Tag' to a policy meant the policy ONLY applied to Executive laptops—it does NOT! Scope Tags only control admin RBAC visibility, never device targeting.",
            "real_world_symptom": "Policy assigned to 'All Devices' with 'Exec-VIP-Tag' quietly applied to all 485 workstations while hiding itself from helpdesk.",
            "recommended_fix": "Separate visibility (Scope Tags) from targeting (Assignment Groups / Intune Filters). Audit all custom-tagged policies assigned to All Devices.",
        },
    ]


def _build_device_persona_findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "PER-001",
            "object_name": "42 Locked-Down AVD Thin-Client Kiosks (Entra Joined, Windows App Only)",
            "severity": "Critical",
            "finding": "Not isolated with an Intune Assignment Filter—receiving corporate Edge, Office, LAPS, and workstation reboot policies via 'All Devices' / 'DYN-All-Corp-Windows11'.",
            "recommended_fix": "Create Intune Assignment Filter 'FLT-Windows-AVD-Kiosks' and attach as Exclude on all standard workstation baselines & Update Rings.",
        },
        {
            "id": "PER-002",
            "object_name": "28 Hybrid AVD Multi-Session Hosts (GPO-Managed + Intune Enrolled)",
            "severity": "High",
            "finding": "Multi-session VDI/AVD hosts enrolled from legacy tenant are receiving single-user workstation BitLocker, sleep, and in-place WUfB policies.",
            "recommended_fix": "Isolate with Assignment Filter 'FLT-Windows-AVD-SessionHosts' (device.operatingSystemSKU -eq 'ServerRdsh') and manage OS patching via golden image rebuilds.",
        },
        {
            "id": "PER-003",
            "object_name": "64 Orphaned ConfigMgr (SCCM) Hybrid Endpoints (Decommissioned Site Server)",
            "severity": "Critical",
            "finding": "Legacy SCCM server was retired, but zombie ccmexec agents + local Registry.pol WSUS/Co-Management keys remain tattooed—silently blocking Intune Update Rings & Compliance.",
            "recommended_fix": "Deploy the Orphaned ConfigMgr & Registry.pol Scrubber remediation script to cleanly uninstall zombie ccmexec and hand MDM precedence to Intune.",
        },
        {
            "id": "PER-004",
            "object_name": "108 Active Co-Managed ConfigMgr + 3rd-Party Cloud Patch Endpoints",
            "severity": "High",
            "finding": "Co-Management Workload Sliders still point Windows Updates & Compliance to ConfigMgr on legacy Forest B while Intune policies also target them.",
            "recommended_fix": "Document exact Co-Management slider ownership per forest and whitelist the 3rd-Party Patch Publisher Enterprise App before enabling Intune MAA.",
        },
        {
            "id": "PER-005",
            "object_name": "17 Dead-Weight Windows 10 Stragglers + Multi-Forest Consolidation Risk",
            "severity": "High",
            "finding": "EOL Windows 10 endpoints distort compliance metrics; meanwhile migrating physical PCs into a new AD root forest only to move to Entra Join later causes double GPO tattooing.",
            "recommended_fix": "Quarantine Win10 into 'FLT-Windows10-EOL-Retirement' and transition refreshed physical laptops straight to Cloud-Native Entra Join + Cloud Kerberos Trust.",
        },
    ]
