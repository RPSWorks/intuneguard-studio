"""Zero-Dependency, XXE-Safe On-Premises Active Directory GPO XML Report Parser.

Parses XML reports exported from Group Policy Management Console (GPMC):
    Get-GPOReport -All -ReportType Xml -Path .\\ad_gpos.xml

Detects tattooed legacy GPO settings that collide with Microsoft Intune CSPs
and Windows Update for Business / Autopatch.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

# Pattern rules: (rule_id, setting_key, severity, regex_patterns, registry_hint, impact)
GPO_COLLISION_RULES: list[tuple[str, str, str, tuple[str, ...], str, str]] = [
    (
        "WSUS_LOCK",
        "wufb_patching_rings_oobe_safe",
        "Critical",
        (r"UseWUServer", r"WUServer", r"DoNotConnectToWindowsUpdateInternetLocations", r"NoAutoUpdate"),
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "Legacy WSUS / Update GPO locks Windows Update winning provider and silently stalls Intune WUfB / Autopatch.",
    ),
    (
        "BITLOCKER_CIPHER",
        "bitlocker_os_xts_aes256_escrow",
        "High",
        (r"EncryptionMethodWithXtsOs", r"OSEncryptionType", r"ActiveDirectoryBackup", r"FVE\\"),
        r"HKLM\SOFTWARE\Policies\Microsoft\FVE",
        "Legacy BitLocker GPO cipher/AD-escrow settings conflict with Intune XTS-AES 256 silent Entra escrow.",
    ),
    (
        "LEGACY_LAPS",
        "windows_laps_entra_rotation",
        "High",
        (r"AdmPwd", r"AdmPwdEnabled", r"Microsoft Services\\AdmPwd"),
        r"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd",
        "Legacy on-prem LAPS (AdmPwd.dll) fights native Windows LAPS Entra ID password rotation.",
    ),
    (
        "FIREWALL_OVERRIDE",
        "windows_firewall_all_profiles",
        "Critical",
        (r"EnableFirewall", r"DomainProfile.*Firewall", r"WindowsFirewall"),
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
        "Legacy Windows Firewall GPO can silently disable Domain/Private profiles or block Intune Firewall merge rules.",
    ),
    (
        "DEFENDER_OVERRIDE",
        "defender_asr_core_rules",
        "Critical",
        (r"DisableRealtimeMonitoring", r"DisableAntiSpyware", r"Windows Defender\\Exclusions"),
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "Legacy Defender GPO disables protection or injects broad exclusions overriding Intune Endpoint Security.",
    ),
    (
        "UAC_RELAXED",
        "uac_secure_desktop_standard_user",
        "High",
        (r"PromptOnSecureDesktop", r"ConsentPromptBehaviorUser", r"EnableLUA"),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "Legacy UAC GPO settings collide with Intune Secure Desktop elevation hardening.",
    ),
    (
        "EDGE_LEGACY",
        "edge_security_baseline_extensions",
        "Medium",
        (r"ExtensionInstallAllowlist", r"SmartScreenEnabled", r"Policies\\Microsoft\\Edge"),
        r"HKLM\SOFTWARE\Policies\Microsoft\Edge",
        "Legacy Edge GPO policy overrides Intune Settings Catalog browser security controls.",
    ),
    (
        "USB_CONTROL",
        "removable_usb_write_control",
        "High",
        (r"RDVDenyWriteAccess", r"RemovableStorageDevices", r"Deny_Write"),
        r"HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE",
        "Legacy Removable Storage GPO collides with Intune Device Control or 3rd-party DLP rules.",
    ),
]


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_gpmc_xml(xml_text: str) -> dict[str, Any]:
    """Safely parse a GPMC XML report (single GPO or -All report) with XXE protection."""
    if not xml_text or not xml_text.strip():
        raise ValueError("Uploaded GPO XML file is empty.")
    if len(xml_text) > 10_000_000:
        raise ValueError("GPO XML exceeds 10 MB safety limit.")

    # Reject XML External Entities / DTD declarations (InfoSec / ARB safeguard)
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", xml_text, flags=re.IGNORECASE):
        raise ValueError("XML DTD / ENTITY declarations are blocked for security (XXE prevention).")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid GPMC XML format: {exc}") from exc

    gpo_elements: list[ET.Element] = []
    if _local_tag(root.tag) == "GPO":
        gpo_elements = [root]
    else:
        for elem in root.iter():
            if _local_tag(elem.tag) == "GPO":
                gpo_elements.append(elem)

    if not gpo_elements:
        raise ValueError(
            "No <GPO> elements found. Export using PowerShell: Get-GPOReport -All -ReportType Xml -Path .\\ad_gpos.xml"
        )

    findings: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()

    for gpo_el in gpo_elements:
        gpo_name = "Unnamed GPO"
        for child in gpo_el:
            if _local_tag(child.tag) == "Name" and child.text:
                gpo_name = child.text.strip()
                break

        blob = ET.tostring(gpo_el, encoding="unicode")
        for _rule_id, setting_key, severity, patterns, reg_hint, impact in GPO_COLLISION_RULES:
            matched_token = None
            for pat in patterns:
                if re.search(pat, blob, flags=re.IGNORECASE):
                    matched_token = pat
                    break
            if matched_token and (gpo_name, setting_key) not in seen_pairs:
                seen_pairs.add((gpo_name, setting_key))
                findings.append(
                    {
                        "gpo_name": gpo_name,
                        "setting_key": setting_key,
                        "registry_path": f"{reg_hint} (matched: {matched_token})",
                        "impact": impact,
                        "severity": severity,
                    }
                )

    return {
        "gpos_scanned": len(gpo_elements),
        "collisions_found": len(findings),
        "tattooed_gpos": findings,
    }
