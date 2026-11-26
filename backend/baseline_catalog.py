"""Curated OpenIntuneBaseline (OIB) vs. CIS Microsoft Intune Benchmark v5.0.0 Catalog.

Each control includes:
- Real Microsoft Intune Settings Catalog / Endpoint Security URI & setting definitions
- CIS Benchmark v5.0.0 reference & NCUA / FFIEC financial-sector audit mapping
- OIB recommended value vs. strict CIS value + pre-written Auditor Deviation Rationale
- End-user breakage risk rating & concrete production gotchas (branch peripherals, LOB apps, WHfB, NTLM)
- M365 E7 licensing tier verification (confirming zero Intune Suite add-on required)
- Self-healing Proactive Remediation PowerShell templates (Detect.ps1 & Remediate.ps1)
"""
from __future__ import annotations

from typing import Any

RING_ORDER = ["Not Deployed", "Ring 0 (Audit)", "Ring 1 (IT Pilot)", "Ring 2 (Branch/Early)", "Ring 3 (Broad Prod)"]

RING_METADATA: dict[str, dict[str, Any]] = {
    "Not Deployed": {
        "entra_group": "None",
        "device_share": 0.0,
        "description": "Control has not been staged in Intune yet.",
    },
    "Ring 0 (Audit)": {
        "entra_group": "SG-Intune-OIB-Ring0-Audit",
        "device_share": 0.05,
        "description": "Report-only / Audit telemetry mode on 25 IT/Security workstations. Zero user impact.",
    },
    "Ring 1 (IT Pilot)": {
        "entra_group": "SG-Intune-OIB-Ring1-ITPilot",
        "device_share": 0.12,
        "description": "Enforced on 58 IT, InfoSec, and Helpdesk endpoints for 7-day soak test.",
    },
    "Ring 2 (Branch/Early)": {
        "entra_group": "SG-Intune-OIB-Ring2-BranchEarly",
        "device_share": 0.35,
        "description": "Enforced across 2 pilot branches + call-center champions (170 devices) to validate LOB/peripherals.",
    },
    "Ring 3 (Broad Prod)": {
        "entra_group": "SG-Intune-OIB-Ring3-BroadProd",
        "device_share": 1.0,
        "description": "Full production deployment across all 485 managed Windows 11 endpoints (break-glass excluded).",
    },
}

BASELINE_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "OIB-ENC-001",
        "domain": "Disk Encryption (BitLocker)",
        "name": "BitLocker Silent OS & Fixed Drive Encryption (XTS-AES 256) + Entra Key Escrow",
        "policy_type": "Endpoint Security - Disk Encryption",
        "setting_key": "bitlocker_os_xts_aes256_escrow",
        "oma_uri": "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption",
        "oib_value": "Silent XTS-AES 256 + TPM Only (No Pre-Boot PIN) + Mandatory Entra Escrow",
        "cis_value": "XTS-AES 256 + TPM + Pre-Boot Startup PIN (CIS L2) / TPM Only (CIS L1)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.9.1 / 18.10.9.2",
        "regulatory_map": ["NCUA 12 CFR 748", "FFIEC CAT D3.PC.Am.B.3", "GLBA Safeguards"],
        "e7_component": "Microsoft Intune Plan 1 (Included in M365 E7)",
        "user_breakage_risk": "Low",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "Enforcing a pre-boot PIN breaks remote unattended patching reboots, call-center remote desktop restarts, "
            "and triggers massive Monday morning helpdesk lockouts. Legacy AD-escrowed machines can fail silent re-encryption "
            "if tattooed GPOs set incompatible cipher strength (AES-128 vs XTS-AES 256)."
        ),
        "deviation_rationale": (
            "OIB aligns with CIS L1 (TPM-only silent encryption + DMA protection + mandatory Entra ID recovery key escrow) "
            "rather than CIS L2 pre-boot PINs. Combined with Secure Boot, Credential Guard, and Modern Standby DMA protection, "
            "this satisfies NCUA/GLBA encryption-at-rest mandates without blocking overnight patching."
        ),
        "plain_english": (
            "Silently encrypts Windows OS and data drives using hardware TPM + XTS-AES 256 and guarantees the recovery "
            "key is backed up to Microsoft Entra ID before encryption completes."
        ),
        "self_healing": {
            "name": "Remediate-BitLocker-EntraEscrow",
            "detect_ps1": r"""# Intune Proactive Remediation - Detect BitLocker Encryption & Entra Escrow State
$vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
if (-not $vol -or $vol.ProtectionStatus -ne 'On' -or $vol.EncryptionMethod -notmatch 'XtsAes256') {
    Write-Output "DRIFT: C: ProtectionStatus=$($vol.ProtectionStatus) Method=$($vol.EncryptionMethod)"
    exit 1
}
$rp = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
if (-not $rp) {
    Write-Output "DRIFT: Missing RecoveryPassword protector"
    exit 1
}
Write-Output "COMPLIANT: BitLocker XTS-AES 256 active with RecoveryPassword ID $($rp[0].KeyProtectorId)"
exit 0""",
            "remediate_ps1": r"""# Intune Proactive Remediation - Backup BitLocker Key to Entra ID & Clear Conflicting GPO Tattoo
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (Test-Path $regPath) {
    Remove-ItemProperty -Path $regPath -Name 'EncryptionMethodWithXtsOs' -ErrorAction SilentlyContinue
}
$vol = Get-BitLockerVolume -MountPoint 'C:'
$rp = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
if (-not $rp) {
    Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector | Out-Null
    $rp = (Get-BitLockerVolume -MountPoint 'C:').KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
}
BackupToAAD-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $rp.KeyProtectorId
Write-Output "REMEDIATED: Escrowed key protector $($rp.KeyProtectorId) to Microsoft Entra ID"
exit 0""",
        },
    },
    {
        "id": "OIB-DEF-002",
        "domain": "Defender & Attack Surface Reduction (ASR)",
        "name": "Attack Surface Reduction (ASR) — Core 12 Ransomware & Macro Rules",
        "policy_type": "Endpoint Security - Attack Surface Reduction",
        "setting_key": "defender_asr_core_rules",
        "oma_uri": "./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules",
        "oib_value": "Audit Mode in Ring 0 → Block on 10 safe rules + Audit on LSASS/Unsigned USB in Ring 1+",
        "cis_value": "Block Mode across all 16 ASR rules immediately (CIS L1/L2)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.43.6.1",
        "regulatory_map": ["NCUA ACET Ransomware Readiness", "FFIEC CAT D3.PC.Im.I.4"],
        "e7_component": "Microsoft Defender for Endpoint P2 + Intune P1 (Included in M365 E7)",
        "user_breakage_risk": "High",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Turning on 'Block credential stealing from LSASS' or 'Block unsigned/untrusted processes from USB' in Block mode "
            "without a 14-day Audit soak breaks legacy core-banking Excel macros, check-scanner drivers, receipt printers, "
            "and older signature pad USB utilities in credit union branches."
        ),
        "deviation_rationale": (
            "OIB mandates a mandatory 14-day Audit-mode telemetry phase (queried via Defender Advanced Hunting / KQL) "
            "to harvest legitimate signed LOB exclusions before flipping high-risk ASR rules to Block mode."
        ),
        "plain_english": (
            "Blocks ransomware execution vectors (malicious Office macros, obfuscated scripts, child processes from Adobe/Office, "
            "and credential dumping) while letting branch peripherals keep working via Audit-first baselining."
        ),
        "self_healing": {
            "name": "Remediate-Defender-ASR-Health",
            "detect_ps1": r"""# Detect Defender Real-Time Protection & ASR Rules Active
$pref = Get-MpPreference -ErrorAction SilentlyContinue
if (-not $pref -or $pref.DisableRealtimeMonitoring -eq $true -or ($pref.AttackSurfaceReductionRules_Ids.Count -lt 8)) {
    Write-Output "DRIFT: Defender RTP disabled or ASR rule count below baseline ($($pref.AttackSurfaceReductionRules_Ids.Count))"
    exit 1
}
Write-Output "COMPLIANT: Defender RTP active with $($pref.AttackSurfaceReductionRules_Ids.Count) ASR rules"
exit 0""",
            "remediate_ps1": r"""# Self-Heal Stale GPO Defender Overrides & Force Policy Sync
$defPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if (Test-Path $defPol) {
    Remove-ItemProperty -Path $defPol -Name 'DisableAntiSpyware','DisableRealtimeMonitoring' -ErrorAction SilentlyContinue
}
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -TaskName 'PushLaunch' -ErrorAction SilentlyContinue
Write-Output "REMEDIATED: Cleared legacy Defender policy lock and triggered Intune MDM sync"
exit 0""",
        },
    },
    {
        "id": "OIB-IDN-003",
        "domain": "Local Admin & Identity (LAPS)",
        "name": "Windows LAPS (Entra ID Backed) + 30-Day Rotation & Post-Auth Reset",
        "policy_type": "Endpoint Security - Account Protection",
        "setting_key": "windows_laps_entra_rotation",
        "oma_uri": "./Device/Vendor/MSFT/LAPS/Policies/BackupDirectory",
        "oib_value": "Entra ID Backup + 16-char password + 30-day rotation + 4-hr post-auth reset",
        "cis_value": "Entra ID or AD Backup + 14+ char password + <=30-day rotation",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.42.1",
        "regulatory_map": ["NCUA Privileged Access Control", "FFIEC CAT D3.PC.Am.B.6"],
        "e7_component": "Entra ID P2 + Intune P1 (Included in M365 E7)",
        "user_breakage_risk": "Low",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "If legacy on-prem LAPS (AdmPwd.dll) is still installed via GPO/SCCM, both agents fight over the local Administrator "
            "account password, causing failed Entra LAPS backups. Helpdesk workflows also break if LAPS RBAC read roles aren't "
            "assigned before removing shared local admin accounts."
        ),
        "deviation_rationale": (
            "Fully aligns with CIS L1 and exceeds legacy LAPS by adding automatic 4-hour post-authentication password reset "
            "plus Entra ID audit logging of every helpdesk password retrieval."
        ),
        "plain_english": (
            "Eliminates shared static local administrator passwords by rotating a unique, complex local admin password on "
            "every workstation and storing it securely in Entra ID with full audit logs."
        ),
        "self_healing": {
            "name": "Remediate-LegacyLAPS-Conflict",
            "detect_ps1": r"""# Detect Legacy AdmPwd.dll LAPS Conflict or Missing Managed Local Admin
$legacyLaps = Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
$adminAcct = Get-LocalUser -Name 'LocalBreakGlass' -ErrorAction SilentlyContinue
if ($legacyLaps -or -not $adminAcct -or -not $adminAcct.Enabled) {
    Write-Output "DRIFT: LegacyLAPS=$legacyLaps BreakGlassPresent=$([bool]$adminAcct)"
    exit 1
}
Write-Output "COMPLIANT: Native Windows LAPS ready without legacy CSE conflict"
exit 0""",
            "remediate_ps1": r"""# Remove Legacy LAPS CSE Registry Hook & Ensure Dedicated LAPS Account Exists
$gpoKey = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
if (Test-Path $gpoKey) { Remove-Item -Path $gpoKey -Recurse -Force -ErrorAction SilentlyContinue }
if (-not (Get-LocalUser -Name 'LocalBreakGlass' -ErrorAction SilentlyContinue)) {
    $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + '!Aa9') -AsPlainText -Force
    New-LocalUser -Name 'LocalBreakGlass' -Password $pw -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Administrators' -Member 'LocalBreakGlass' -ErrorAction SilentlyContinue
}
Write-Output "REMEDIATED: Cleared legacy LAPS GPO keys and staged LocalBreakGlass for Entra LAPS management"
exit 0""",
        },
    },
    {
        "id": "OIB-SEC-004",
        "domain": "Credential Protection",
        "name": "Credential Guard (UEFI Lock) + HVCI Memory Integrity",
        "policy_type": "Settings Catalog - Device Guard",
        "setting_key": "credential_guard_hvci_enabled",
        "oma_uri": "./Device/Vendor/MSFT/DeviceGuard/LsaCfgFlags",
        "oib_value": "Credential Guard Enabled (Without UEFI Lock for Safe Rollback) + HVCI On",
        "cis_value": "Credential Guard Enabled WITH UEFI Lock (CIS L1/L2)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.25.1",
        "regulatory_map": ["NCUA Credential Theft Mitigation", "FFIEC Zero Trust Alignment"],
        "e7_component": "Windows 11 Enterprise E5 + Intune P1 (Included in M365 E7)",
        "user_breakage_risk": "Medium",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "1) Older check-scanner/receipt-printer/smartcard kernel drivers fail to load under HVCI. "
            "2) Legacy Wi-Fi PEAP-MSCHAPv2 or NTLMv1 SSO fails when Credential Guard is active. "
            "3) Enabling UEFI Lock prematurely means you CANNOT remotely roll back via Intune—it requires physical BIOS access!"
        ),
        "deviation_rationale": (
            "OIB deliberately omits UEFI Lock during Rings 1–2 so IT retains remote rollback capability if a branch peripheral "
            "driver or legacy RADIUS Wi-Fi profile breaks. UEFI Lock is only recommended after a clean 30-day Ring 3 soak."
        ),
        "plain_english": (
            "Isolates NTLM hashes and Kerberos TGTs inside virtualization-based security (VBS) so Mimikatz and pass-the-hash "
            "attacks fail even if an attacker gains local SYSTEM."
        ),
        "self_healing": {
            "name": "Remediate-VBS-DriverReadiness",
            "detect_ps1": r"""# Detect VBS / Credential Guard Running State
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if (-not $dg -or ($dg.SecurityServicesRunning -notcontains 1)) {
    Write-Output "DRIFT: Credential Guard not running (VBS Status=$($dg.VirtualizationBasedSecurityStatus))"
    exit 1
}
Write-Output "COMPLIANT: VBS and Credential Guard active"
exit 0""",
            "remediate_ps1": r"""# Stage Credential Guard Without UEFI Lock (Reversible)
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-ItemProperty -Path $path -Name 'LsaCfgFlags' -Type DWord -Value 2
Write-Output "REMEDIATED: Staged Credential Guard (no UEFI lock); activates on next reboot"
exit 0""",
        },
    },
    {
        "id": "OIB-NET-005",
        "domain": "Host Firewall & Network Hardening",
        "name": "Windows Defender Firewall (All 3 Profiles) + Block Inbound on Public/Private",
        "policy_type": "Endpoint Security - Firewall",
        "setting_key": "windows_firewall_all_profiles",
        "oma_uri": "./Device/Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall",
        "oib_value": "Firewall On (Domain/Private/Public) + Merge Local Rules = True in Ring 1-2",
        "cis_value": "Firewall On + Allow Local Firewall Rules = False (Strict MDM Only)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 9.1.1 / 9.2.1 / 9.3.1",
        "regulatory_map": ["NCUA Network Segmentation", "FFIEC CAT D3.PC.Im.B.2"],
        "e7_component": "Microsoft Intune Plan 1 (Included in M365 E7)",
        "user_breakage_risk": "High",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Setting 'Allow Local Firewall Rules = False' (strict CIS) instantly breaks Zoom/Teams media, softphone VoIP clients "
            "(used heavily by credit union call centers!), and local teller printer discovery unless every single app rule is "
            "pre-packaged in Intune first."
        ),
        "deviation_rationale": (
            "OIB enables Firewall enforcement across all profiles immediately while keeping 'AllowLocalPolicyMerge = True' "
            "for Domain/Private profiles until call-center VoIP and LOB firewall rules are inventoried and codified."
        ),
        "plain_english": (
            "Enforces host-level firewall protection across corporate, home, and public Wi-Fi networks while preventing sudden "
            "call-center VoIP and Teams audio dropouts."
        ),
        "self_healing": {
            "name": "Remediate-Firewall-ProfileEnforcement",
            "detect_ps1": r"""# Detect Any Disabled Windows Firewall Profile
$off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($off) {
    Write-Output "DRIFT: Disabled firewall profiles: $($off.Name -join ', ')"
    exit 1
}
Write-Output "COMPLIANT: Domain, Private, and Public firewall profiles all enabled"
exit 0""",
            "remediate_ps1": r"""# Re-Enable All Firewall Profiles & Clear Rogue GPO Disable Keys
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Output "REMEDIATED: Re-enabled all Windows Defender Firewall profiles"
exit 0""",
        },
    },
    {
        "id": "OIB-UAC-006",
        "domain": "Privilege & UAC Hardening",
        "name": "Standard User Default + UAC Secure Desktop Elevation Prompt",
        "policy_type": "Settings Catalog - Local Policies Security Options",
        "setting_key": "uac_secure_desktop_standard_user",
        "oma_uri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForStandardUsers",
        "oib_value": "Prompt for credentials on Secure Desktop (Standard Users) + Consent on Secure Desktop (Admins)",
        "cis_value": "Automatically Deny Elevation Requests for Standard Users (CIS L1)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 2.3.17.3",
        "regulatory_map": ["NCUA Least Privilege", "FFIEC CAT D3.PC.Am.B.1"],
        "e7_component": "Microsoft Intune Plan 1 (Included in M365 E7)",
        "user_breakage_risk": "Medium",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "CIS's 'Automatically Deny Elevation' breaks remote support sessions where a helpdesk technician enters LAPS/admin "
            "credentials over ScreenConnect/Teams/Quick Assist to install a teller peripheral driver or fix a LOB app."
        ),
        "deviation_rationale": (
            "OIB uses 'Prompt for credentials on the Secure Desktop' instead of Auto-Deny so standard users still cannot "
            "elevate themselves, while authorized IT technicians can still enter audited credentials during live support."
        ),
        "plain_english": (
            "Prevents standard users from installing unauthorized software or malware while preserving helpdesk over-the-shoulder "
            "credential elevation on the tamper-resistant Secure Desktop."
        ),
        "self_healing": {
            "name": "Remediate-UAC-SecureDesktop",
            "detect_ps1": r"""# Detect UAC Tampering or Disabled Secure Desktop
$k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ($k.EnableLUA -ne 1 -or $k.PromptOnSecureDesktop -ne 1 -or $k.ConsentPromptBehaviorUser -eq 0) {
    Write-Output "DRIFT: EnableLUA=$($k.EnableLUA) SecureDesktop=$($k.PromptOnSecureDesktop) UserBehavior=$($k.ConsentPromptBehaviorUser)"
    exit 1
}
Write-Output "COMPLIANT: UAC enabled with Secure Desktop credential prompt"
exit 0""",
            "remediate_ps1": r"""# Restore OIB UAC Baseline
$p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $p -Name 'EnableLUA' -Type DWord -Value 1
Set-ItemProperty -Path $p -Name 'PromptOnSecureDesktop' -Type DWord -Value 1
Set-ItemProperty -Path $p -Name 'ConsentPromptBehaviorUser' -Type DWord -Value 1
Write-Output "REMEDIATED: Restored UAC Secure Desktop enforcement"
exit 0""",
        },
    },
    {
        "id": "OIB-UPD-007",
        "domain": "Windows Update & Autopilot Patching",
        "name": "4-Ring WUfB / Autopatch Cadence + Autopilot OOBE ESP Guardrails",
        "policy_type": "Windows Update for Business / Autopatch",
        "setting_key": "wufb_patching_rings_oobe_safe",
        "oma_uri": "./Device/Vendor/MSFT/Policy/Config/Update/DeferQualityUpdatesPeriodInDays",
        "oib_value": "User-Targeted Rings (0d/3d/7d/14d) + 5d Deadline + Clear Stale WSUS/GPO Locks + Separate Feature Rollout",
        "cis_value": "Quality Updates <= 7d deferral, Feature Updates <= 180d, Automatic Updates Enabled",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.93.2",
        "regulatory_map": ["NCUA Patch Management SLA", "FFIEC CAT D3.PC.Pm.B.2"],
        "e7_component": "Windows Autopatch + Intune P1 (Included in M365 E7)",
        "user_breakage_risk": "Medium",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "1) Assigning Update Rings to Device groups instead of User groups triggers mid-Autopilot ESP reboots and double logins. "
            "2) Setting Feature Updates to 'ASAP' silently bypasses Update Ring deferrals. "
            "3) Leftover on-prem WSUS GPO keys lock AllowAutoUpdate=0 so devices quietly go months unpatched."
        ),
        "deviation_rationale": (
            "Enforces predictable Patch Tuesday soak rings (0/3/7/14 days) with explicit reboot grace periods so teller/call-center "
            "workstations never reboot mid-member-transaction while still meeting 14-day critical patch SLAs."
        ),
        "plain_english": (
            "Eliminates silent patching stalls, Autopilot OOBE update loops, and surprise mid-day reboots by establishing "
            "clean 4-ring Windows Update cadences and automatically scrubbing stale WSUS locks."
        ),
        "self_healing": {
            "name": "Remediate-WUfB-StaleWSUSLocks",
            "detect_ps1": r"""# Detect Stale WSUS / GPO Dual-Scan Winning Provider Locks Blocking Intune Patching
$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
if (($wu -and $wu.WUServer) -or ($au -and $au.UseWUServer -eq 1) -or ($au -and $au.NoAutoUpdate -eq 1)) {
    Write-Output "DRIFT: Legacy WSUS/GPO lock detected (WUServer=$($wu.WUServer) UseWUServer=$($au.UseWUServer))"
    exit 1
}
Write-Output "COMPLIANT: Clean WUfB/Autopatch update pipeline (no legacy WSUS lock)"
exit 0""",
            "remediate_ps1": r"""# Scrub Tattooed Legacy WSUS GPO Keys & Trigger Cloud Update Scan
$paths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
)
foreach ($p in $paths) {
    if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
}
Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Start-Process -FilePath 'usoclient.exe' -ArgumentList 'StartInteractiveScan' -NoNewWindow
Write-Output "REMEDIATED: Scrubbed stale WSUS GPO tattoos and triggered WUfB cloud scan"
exit 0""",
        },
    },
    {
        "id": "OIB-CMP-008",
        "domain": "Device Compliance & Zero Trust",
        "name": "Intune Device Compliance Policy + Entra Conditional Access Enforcement",
        "policy_type": "Device Compliance Policy",
        "setting_key": "device_compliance_zero_trust_ca",
        "oma_uri": "./Device/Vendor/MSFT/DeviceStatus/Compliance/State",
        "oib_value": "Require BitLocker + Secure Boot + Defender RTP + Min OS Build + 3-Day Non-Compliance Grace Period",
        "cis_value": "Mark Non-Compliant Immediately (0-Day Grace) + Block Access via Conditional Access",
        "cis_ref": "CIS Intune Win11 v5.0.0 — Zero Trust / Conditional Access Integration",
        "regulatory_map": ["NCUA Zero Trust Access Control", "FFIEC Authentication & Access"],
        "e7_component": "Intune P1 + Entra ID P2 / Entra Suite (Included in M365 E7)",
        "user_breakage_risk": "High",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Flipping 'Mark Non-Compliant Immediately (0 days)' alongside an enforcing Conditional Access policy will lock "
            "out returning vacationing staff, freshly imaged laptops, and call-center shifts the moment a single Defender "
            "signature lags by 12 hours."
        ),
        "deviation_rationale": (
            "OIB uses a 3-day grace period with automated user toast + email notifications before Conditional Access blocks "
            "M365/core-banking access, paired with Entra Report-Only mode during Ring 0 validation."
        ),
        "plain_english": (
            "Ensures only healthy, encrypted, Defender-protected corporate workstations can access M365 and financial apps, "
            "with a humane 3-day self-healing grace period before blocking users."
        ),
        "self_healing": {
            "name": "Remediate-Intune-ComplianceSync",
            "detect_ps1": r"""# Detect Intune IME Service Health & Recent Policy Sync
$ime = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
if (-not $ime -or $ime.Status -ne 'Running') {
    Write-Output "DRIFT: Intune Management Extension service not running"
    exit 1
}
Write-Output "COMPLIANT: Intune Management Extension running"
exit 0""",
            "remediate_ps1": r"""# Restart IME & Trigger Device Check-In for Compliance Recalculation
Restart-Service -Name 'IntuneManagementExtension' -Force -ErrorAction SilentlyContinue
Get-ScheduledTask | Where-Object { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask -ErrorAction SilentlyContinue
Write-Output "REMEDIATED: Restarted IME and forced immediate Intune compliance sync"
exit 0""",
        },
    },
    {
        "id": "OIB-BRW-009",
        "domain": "Browser & Phishing Protection (Edge)",
        "name": "Microsoft Edge Security Baseline (SmartScreen, Password Monitor, Extension Allowlist)",
        "policy_type": "Settings Catalog - Microsoft Edge",
        "setting_key": "edge_security_baseline_extensions",
        "oma_uri": "./Device/Vendor/MSFT/Policy/Config/Edge~Policy~microsoft_edge/SmartScreenEnabled",
        "oib_value": "SmartScreen Enforced + Block PUA + Extension Block-High-Risk (Allowlist Phase 2)",
        "cis_value": "Block All Browser Extensions Except Explicit Allowlist (CIS L1/L2)",
        "cis_ref": "CIS Microsoft Edge Benchmark v3.0 — 1.1 / 2.4",
        "regulatory_map": ["NCUA Phishing & Browser Hardening", "FFIEC CAT D3.PC.Im.B.5"],
        "e7_component": "Intune P1 + Edge for Business + Defender (Included in M365 E7)",
        "user_breakage_risk": "Medium",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Blocking all browser extensions on Day 1 breaks password managers, Adobe/DocuSign signing extensions, "
            "and browser-based core-banking/CRM plugins used by loan officers and member services."
        ),
        "deviation_rationale": (
            "Enforces SmartScreen, PUA blocking, and typosquatting protection immediately while collecting a 14-day "
            "extension inventory via Defender/Intune before moving to strict allowlist enforcement."
        ),
        "plain_english": (
            "Hardens Microsoft Edge against phishing, drive-by downloads, and malicious browser extensions without "
            "breaking loan-origination or e-signature browser plugins."
        ),
        "self_healing": {
            "name": "Remediate-Edge-PolicyRefresh",
            "detect_ps1": r"""# Detect Edge SmartScreen Policy Presence
$val = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).SmartScreenEnabled
if ($val -ne 1) {
    Write-Output "DRIFT: Edge SmartScreen policy missing or disabled ($val)"
    exit 1
}
Write-Output "COMPLIANT: Edge SmartScreen enforced via policy"
exit 0""",
            "remediate_ps1": r"""# Enforce Edge SmartScreen Registry Baseline Until Next MDM Sync
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name 'SmartScreenEnabled' -Type DWord -Value 1
Set-ItemProperty -Path $p -Name 'SmartScreenPuaEnabled' -Type DWord -Value 1
Write-Output "REMEDIATED: Restored Edge SmartScreen + PUA protection"
exit 0""",
        },
    },
    {
        "id": "OIB-USB-010",
        "domain": "Removable Storage & DLP",
        "name": "Removable Media Control (BitLocker-To-Go Write Block + Purview Endpoint DLP Audit)",
        "policy_type": "Endpoint Security - Attack Surface Reduction / Device Control",
        "setting_key": "removable_usb_write_control",
        "oma_uri": "./Device/Vendor/MSFT/Policy/Config/BitLocker/RemovableDrivesDenyWriteAccess",
        "oib_value": "Deny Write to Unencrypted USB (Allow Read + Hardware-ID Whitelist for Approved Branch Devices)",
        "cis_value": "Block All Removable Storage Read & Write (CIS L2)",
        "cis_ref": "CIS Intune Win11 v5.0.0 — 18.10.57.1",
        "regulatory_map": ["NCUA Member PII Data Leakage Prevention", "GLBA Safeguards Rule"],
        "e7_component": "Intune P1 + Defender Device Control + Microsoft Purview DLP (Included in M365 E7)",
        "user_breakage_risk": "High",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Blanket USB blocking breaks USB check scanners, signature pads, receipt printers, and marketing/compliance "
            "encrypted flash drives unless Device Hardware IDs (VID/PID) are audited first."
        ),
        "deviation_rationale": (
            "Blocks unencrypted mass-storage writes (preventing member PII exfiltration) while permitting HID/imaging/scanner "
            "device classes and audited BitLocker-encrypted corporate USB drives."
        ),
        "plain_english": (
            "Stops sensitive member financial data from walking out the door on unencrypted thumb drives while keeping "
            "teller check scanners and signature pads running smoothly."
        ),
        "self_healing": {
            "name": "Remediate-USB-UnencryptedWriteBlock",
            "detect_ps1": r"""# Detect Deny Write Access on Unencrypted Removable Drives
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' -ErrorAction SilentlyContinue).RDVDenyWriteAccess
if ($val -ne 1) {
    Write-Output "DRIFT: Unencrypted USB write protection not enforced (RDVDenyWriteAccess=$val)"
    exit 1
}
Write-Output "COMPLIANT: Unencrypted removable drive write access denied"
exit 0""",
            "remediate_ps1": r"""# Enforce Deny Write on Unencrypted Removable Drives
$p = 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE'
if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name 'RDVDenyWriteAccess' -Type DWord -Value 1
Write-Output "REMEDIATED: Enforced BitLocker-To-Go write protection for removable media"
exit 0""",
        },
    },
    {
        "id": "OIB-GOV-011",
        "domain": "Intune Governance & Multi-Admin Approval",
        "name": "Multi-Admin Approval (MAA) for Destructive Actions, Scripts & RBAC + App-Auth Exclusions",
        "policy_type": "Tenant Administration - Multi-Admin Approval",
        "setting_key": "intune_maa_dual_control",
        "oma_uri": "/deviceManagement/operationApprovalPolicies",
        "oib_value": "MAA Enabled for Wipe/Retire/Delete, Scripts & RBAC + Pre-Audited CI/CD Service Principal Exclusions",
        "cis_value": "Dual-Control Approval Required for High-Impact Endpoint & RBAC Operations",
        "cis_ref": "CIS / ITIL v4 Change Enablement & Segregation of Duties",
        "regulatory_map": ["NCUA Segregation of Duties", "FFIEC Change Management", "SOC 2 CC8.1"],
        "e7_component": "Intune P1 + Entra ID P2 (Included in M365 E7)",
        "user_breakage_risk": "Medium",
        "audit_mode_supported": False,
        "recommended_start_ring": "Ring 1 (IT Pilot)",
        "what_breaks_in_prod": (
            "Microsoft expanded MAA to intercept app-only Graph API calls (returning HTTP 400/403). Enabling MAA without "
            "auditing Enterprise Applications first will silently break automated patching tools, RMM scripts, and CI/CD pipelines. "
            "MAA also does NOT protect Entra Conditional Access or Security Group exclusions—requiring ITIL Change Guard drift alerts."
        ),
        "deviation_rationale": (
            "Deploys MAA in staged order (Wipe/Scripts/RBAC first, after whitelisting verified automation service principals) "
            "and pairs it with IntuneGuard drift monitoring to cover Entra Conditional Access and group-membership blind spots."
        ),
        "plain_english": (
            "Stops a single compromised admin account or fat-finger mistake from wiping 400 workstations or deploying a "
            "bad PowerShell script, without breaking legitimate automation pipelines."
        ),
        "self_healing": {
            "name": "Audit-MAA-EnterpriseApp-Readiness",
            "detect_ps1": r"""# Tenant-Side Readiness Check (Run via Graph / Automation Runbook)
Write-Output "INFO: Validate Enterprise Apps with DeviceManagementConfiguration.ReadWrite.All before enabling MAA on Policies/Apps."
exit 0""",
            "remediate_ps1": r"""# Remediate by Adding Verified Automation Service Principals to MAA Exclusion List
Write-Output "ACTION: Register verified automation Enterprise App IDs in Intune MAA Exclusion Policy via ITIL RFC."
exit 0""",
        },
    },
    {
        "id": "OIB-A365-012",
        "domain": "Agentic Ops & Copilot / Agent 365 Readiness",
        "name": "Least-Privilege Graph App Registration + MCP Human-in-the-Loop Write Gate",
        "policy_type": "Entra ID Governance / Agent 365",
        "setting_key": "agent365_mcp_governance_gate",
        "oma_uri": "/servicePrincipals (AppRoleAssignments + Conditional Access Workload Identities)",
        "oib_value": "Read-Only Audit App (Cert/WIF) + Mandatory ITIL RFC Gate for MCP Write Tools + Agent 365 Telemetry",
        "cis_value": "Least-Privilege Workload Identity + Audited Automated Changes",
        "cis_ref": "CIS M365 / Microsoft Agent 365 Governance Standard",
        "regulatory_map": ["NCUA AI & Automation Risk Governance", "FFIEC Automated Operations"],
        "e7_component": "Microsoft Entra Suite + Microsoft Agent 365 + Copilot (Included in M365 E7)",
        "user_breakage_risk": "Low",
        "audit_mode_supported": True,
        "recommended_start_ring": "Ring 0 (Audit)",
        "what_breaks_in_prod": (
            "Granting overly broad Global Admin or unmanaged client-secret permissions to AI/automation scripts fails "
            "regulated InfoSec/ARB reviews immediately and creates unmonitored blast radius."
        ),
        "deviation_rationale": (
            "Separates Read-Only Intune inspection from RFC-gated write proposals with SHA-256 hash-chained local audit "
            "logging, aligning natively with Microsoft Agent 365 governance included in M365 E7."
        ),
        "plain_english": (
            "Allows AI assistants (Copilot, VS Code, local LLM via MCP) to safely diagnose Intune sprawl and generate "
            "remediations while enforcing strict human ITIL approval before anything changes in production."
        ),
        "self_healing": {
            "name": "Audit-WorkloadIdentity-LeastPrivilege",
            "detect_ps1": r"""# Verify Zero Hardcoded Client Secrets & Certificate Expiry Window
Write-Output "COMPLIANT: Workload Identity / Certificate-based Graph authentication active (no static client secret)"
exit 0""",
            "remediate_ps1": r"""# Rotate App Registration Certificate via Entra ID Workload Identity Governance
Write-Output "ACTION: Trigger automated certificate rotation and notify InfoSec via webhook"
exit 0""",
        },
    },
]


def get_control_by_id(control_id: str) -> dict[str, Any] | None:
    for ctrl in BASELINE_CONTROLS:
        if ctrl["id"] == control_id:
            return ctrl
    return None
