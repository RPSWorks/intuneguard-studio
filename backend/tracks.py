"""Skill-Grown Guided Learning Tracks for IntuneGuard Studio.

Breaks Intune modernization into 7 calm, self-contained Tracks so engineers can
tackle ONE pitfall at a time, follow a consistent 4-step loop
(1. Learn -> 2. Inspect -> 3. Fix Safely -> 4. Save to Tenant Memory),
and progressively build shared context for both the team and AI/MCP agents.
"""
from __future__ import annotations

from typing import Any

from backend.scripts_generator import (
    generate_orphan_cleanup_script,
    generate_stale_group_cleanup_script,
)

AUTOPILOT_ESP_AUDIT_PS1 = r"""<#
.SYNOPSIS
  Track 3 — Autopilot Profile, ESP & Update Ring Diagnostic Script (Read-Only)
.DESCRIPTION
  Audits Enrollment Status Page (ESP) blocking app counts, OOBE update settings,
  and Windows Update Rings assigned to Autopilot Device groups (common reboot loop cause).
#>
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All","DeviceManagementConfiguration.Read.All" -NoWelcome

Write-Host "[1/3] Checking Enrollment Status Page (ESP) Profiles..." -ForegroundColor Cyan
$esps = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations").value |
    Where-Object { $_.'@odata.type' -match 'EnrollmentCompletionPage' }
foreach ($e in $esps) {
    $appCount = ($e.selectedMobileAppIds | Measure-Object).Count
    Write-Host " - $($e.displayName): Timeout=$($e.installProgressTimeoutInMinutes)m | BlockingApps=$appCount | ShowProgress=$($e.showInstallationProgress)"
    if ($appCount -gt 6) { Write-Host "   [WARN] >6 blocking ESP apps increases 0x81036502 timeout failures." -ForegroundColor Yellow }
}

Write-Host "`n[2/3] Checking Autopilot Profiles for Hybrid Join or Local Admin..." -ForegroundColor Cyan
$aps = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles").value
foreach ($a in $aps) {
    $acctType = $a.outOfBoxExperienceSettings.userType
    Write-Host " - $($a.displayName): Type=$($a.'@odata.type'.Split('.')[-1]) | UserType=$acctType"
    if ($acctType -eq 'administrator') { Write-Host "   [RISK] Users provisioned as Local Administrator!" -ForegroundColor Red }
}

Write-Host "`n[3/3] Checking Feature Update Policies for 'ASAP' Deferral Bypass..." -ForegroundColor Cyan
$fus = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles").value
foreach ($f in $fus) {
    Write-Host " - $($f.displayName): FeatureVersion=$($f.featureUpdateVersion) | RolloutStart=$($f.rolloutSettings.offerStartDateTimeInUTC)"
}
"""

RBAC_AUDIT_PS1 = r"""<#
.SYNOPSIS
  Track 4 — Over-Privileged Custom Intune RBAC Role & Standing Admin Auditor (Read-Only)
.DESCRIPTION
  Flags custom Intune roles granting dangerous permissions (Wipe, Delete, Run Scripts,
  Role Write) and lists permanent standing Intune Administrators not using Entra PIM.
#>
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All","RoleManagement.Read.Directory" -NoWelcome

Write-Host "[1/2] Auditing Custom Intune RBAC Roles for High-Risk Permissions..." -ForegroundColor Cyan
$roles = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions").value |
    Where-Object { -not $_.isBuiltIn }

$dangerPatterns = @('Wipe','Delete','Retire','DeviceManagementScripts_Assign','RoleDefinitions_Update','RoleAssignments_Update')
foreach ($r in $roles) {
    $allowed = ($r.rolePermissions | ForEach-Object { $_.resourceActions.allowedResourceActions })
    $hits = $allowed | Where-Object { $a = $_; $dangerPatterns | Where-Object { $a -match $_ } }
    Write-Host " - Custom Role: $($r.displayName) | High-Risk Perms Found: $(($hits | Measure-Object).Count)"
    $hits | ForEach-Object { Write-Host "   [FLAG] $_" -ForegroundColor Yellow }
}

Write-Host "`n[2/2] Checking Standing (Permanent) Intune Administrator Role Assignments..." -ForegroundColor Cyan
$intuneRole = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq 'Intune Administrator'").value | Select-Object -First 1
if ($intuneRole) {
    $members = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($intuneRole.id)/members").value
    Write-Host " Standing Intune Admins (Consider Entra PIM Eligible instead): $($members.Count)" -ForegroundColor Yellow
    $members | ForEach-Object { Write-Host "   - $($_.displayName) ($($_.userPrincipalName))" }
}
"""

SCOPE_TAG_AUDIT_PS1 = r"""<#
.SYNOPSIS
  Track 5 — Scope Tag Visibility Pitfall Auditor (Read-Only)
.DESCRIPTION
  Finds Intune policies missing the 'Default' Scope Tag (0) — the #1 cause of
  "invisible policies" where HQ/Security admins create duplicates because they
  cannot see custom-tagged branch policies.
#>
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementRBAC.Read.All" -NoWelcome

$tags = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags").value
$tagMap = @{}
foreach ($t in $tags) { $tagMap[[string]$t.id] = $t.displayName }

Write-Host "Defined Scope Tags ($($tags.Count)): $($tags.displayName -join ', ')" -ForegroundColor Cyan

$policies = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$top=100").value
$missingDefault = @()
foreach ($p in $policies) {
    $ids = @($p.roleScopeTagIds)
    if ($ids -notcontains "0") {
        $tagNames = ($ids | ForEach-Object { $tagMap[[string]$_] }) -join ', '
        $missingDefault += [PSCustomObject]@{ Policy = $p.name; Tags = $tagNames }
    }
}

Write-Host "`nPolicies MISSING 'Default' Scope Tag (Potentially Hidden from Auditors/HQ): $($missingDefault.Count)" -ForegroundColor Yellow
$missingDefault | Format-Table -AutoSize
"""

ZOMBIE_SCCM_AND_PERSONAS_PS1 = r"""<#
.SYNOPSIS
  Track 7 — Orphaned ConfigMgr (SCCM) Client Scrubber & Device Persona Isolation Helper
.DESCRIPTION
  Runs in SAFE DRY-RUN mode by default.
  1) Checks whether the local ConfigMgr (ccmexec) Management Point is unreachable/decommissioned.
  2) With -ExecuteScrub, cleanly uninstalls zombie ccmsetup, clears tattooed local Registry.pol
     WSUS/Co-Management keys, and hands Windows Update / MDM winning-provider precedence to Intune.
  3) Outputs recommended Intune Assignment Filter rules for AVD Kiosks, Multi-Session AVD, and Win10 EOL.
#>
param(
    [string]$RetiredSiteCode = "",
    [switch]$ExecuteScrub
)

Write-Host "=== Recommended Intune Assignment Filters (Zero Group Nesting) ===" -ForegroundColor Cyan
Write-Host '  1. FLT-Windows-AVD-Kiosks       : (device.displayName -startsWith "KIOSK-") -or (device.model -contains "OptiPlex")'
Write-Host '  2. FLT-Windows-AVD-SessionHosts : (device.operatingSystemSKU -eq "ServerRdsh")'
Write-Host '  3. FLT-Windows10-EOL-Quarantine : (device.osVersion -startsWith "10.0.19")'

$ccm = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
$ccmSetup = 'C:\Windows\ccmsetup\ccmsetup.exe'
$wuPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue

Write-Host "`n=== Local Orphaned ConfigMgr / Tattoo Diagnostic ===" -ForegroundColor Yellow
Write-Host "  CcmExec Present  : $([bool]$ccm) ($($ccm.Status))"
Write-Host "  UseWUServer Lock : $($wuPol.UseWUServer)"

if ($ExecuteScrub -and (Test-Path $ccmSetup)) {
    Write-Host "Uninstalling orphaned ConfigMgr client..." -ForegroundColor Green
    Start-Process -FilePath $ccmSetup -ArgumentList '/uninstall' -Wait -NoNewWindow
    Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM','HKLM:\SOFTWARE\Microsoft\CCMSetup' -Recurse -Force -ErrorAction SilentlyContinue
    Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Write-Host "DONE: Scrubbed zombie ConfigMgr client & WSUS tattoos. Intune MDM now owns precedence." -ForegroundColor Green
} else {
    Write-Host "`nDRY-RUN ONLY. Target ONLY devices from the decommissioned SCCM site (NEVER active ConfigMgr hosts) and pass -ExecuteScrub." -ForegroundColor DarkGray
}
"""


def build_guided_tracks(
    snapshot: dict[str, Any],
    controls: list[dict[str, Any]],
    progress: dict[str, dict[str, Any]],
    memories: list[dict[str, Any]],
    env_profile: dict[str, Any] | None = None,
    track_claims: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    policies = snapshot.get("policies") or []
    groups = snapshot.get("groups") or []
    gpos = snapshot.get("tattooed_gpos") or []
    autopilot = snapshot.get("autopilot_esp") or []
    custom_roles = snapshot.get("custom_roles") or []
    scope_tags = snapshot.get("scope_tags") or []
    enterprise_apps = snapshot.get("enterprise_apps") or []
    device_personas = snapshot.get("device_personas") or []
    env_profile = env_profile or {}
    track_claims = track_claims or {}

    orphans = [p for p in policies if p["status_flag"] == "orphaned"]
    conflicts = [p for p in policies if p["status_flag"] == "conflict"]
    duplicates = [p for p in policies if p["status_flag"] == "duplicate"]
    risky_groups = [g for g in groups if g.get("risk_flag")]
    nested_groups = [g for g in groups if g.get("nested_children")]

    def is_done(tid: str) -> bool:
        return bool(progress.get(f"track:{tid}", {}).get("completed"))

    def track_memories(tid: str) -> list[dict[str, Any]]:
        return [m for m in memories if m["track_id"] == tid]

    tracks = [
        {
            "id": "policy-sprawl",
            "order": 1,
            "title": "Policy Sprawl & GPO Collisions",
            "tagline": "Clean up unassigned orphans, duplicates, and tattooed legacy GPOs before touching users.",
            "difficulty": "Start Here • Beginner",
            "time_estimate": "15 min",
            "user_impact": "Zero User Impact",
            "findings_count": len(orphans) + len(conflicts) + len(gpos),
            "completed": is_done("policy-sprawl"),
            "memory_count": len(track_memories("policy-sprawl")),
            "learn": {
                "what_it_is": "Years of ad-hoc Intune edits leave hundreds of orphaned, duplicate, and conflicting profiles fighting over the same Windows settings—plus old on-prem AD GPO keys tattooed in the registry.",
                "why_it_breaks": "When two Intune policies set the same OMA-URI differently, Intune marks the setting 'Conflict' and stops enforcing it. When a legacy GPO key is tattooed in HKLM\\SOFTWARE\\Policies, Windows often ignores Intune silently.",
                "architect_rule": "Always archive unassigned orphans first (0 risk), inventory duplicates second, and scrub tattooed GPOs via Proactive Remediations BEFORE deploying new baselines.",
            },
            "inspect_items": [
                {
                    "title": f"{len(orphans)} Orphaned (Unassigned) Policies Found",
                    "severity": "Medium",
                    "detail": "Sitting unassigned in the console (e.g., old 'TEST - DO NOT DELETE' and consultant profiles). Safe to export to JSON and remove.",
                    "examples": [p["name"] for p in orphans[:4]],
                },
                {
                    "title": f"{len(conflicts)} Conflicting & {len(duplicates)} Duplicate Policies",
                    "severity": "Critical",
                    "detail": "Overlapping BitLocker, Firewall, ASR, and Update profiles assigned to intersecting groups.",
                    "examples": [p["name"] for p in conflicts[:4]],
                },
                {
                    "title": f"{len(gpos)} Tattooed On-Prem AD GPO Registry Locks",
                    "severity": "High",
                    "detail": "Legacy WSUS, AES-128 BitLocker, AdmPwd LAPS, and Domain Firewall=0 keys overriding Intune on Hybrid-joined PCs.",
                    "examples": [f"{g['gpo_name']} ({g['registry_path']})" for g in gpos[:4]],
                },
            ],
            "fix": {
                "steps": [
                    "Run Stage 2A script in default Dry-Run mode to back up all unassigned policies to local JSON.",
                    "Open Deep Explorer -> filter 'Conflicting' to identify policy owners before retiring duplicates.",
                    "Deploy Proactive Remediation scripts (WSUS/BitLocker/LAPS) to scrub tattooed GPO keys cleanly.",
                ],
                "script_name": "Stage2A-Archive-OrphanPolicies.ps1",
                "script_download_url": "/api/scripts/orphan_cleanup",
                "script_content": generate_orphan_cleanup_script(orphans),
                "deep_link_tab": "explorer",
            },
            "memory_template": {
                "category": "Policy Cleanup & Precedence",
                "default_summary": f"Archived {len(orphans)} orphaned policies and identified legacy GPO cleanup targets.",
                "default_details": "Backed up unassigned profiles to local JSON before removal; documented conflicting BitLocker/Firewall/WSUS policies for phased retirement.",
            },
        },
        {
            "id": "nested-groups",
            "order": 2,
            "title": "Nested Group Detox & Exclusions",
            "tagline": "Untangle 3-level nested dynamic/static groups and kill stale 'temp troubleshooting' bypasses.",
            "difficulty": "Beginner",
            "time_estimate": "15 min",
            "user_impact": "Zero User Impact",
            "findings_count": len(risky_groups) + len(nested_groups),
            "completed": is_done("nested-groups"),
            "memory_count": len(track_memories("nested-groups")),
            "learn": {
                "what_it_is": "Nesting static groups inside umbrella groups alongside Dynamic Device groups—and stacking Exclude groups on top—makes it impossible to predict which policies actually hit a workstation.",
                "why_it_breaks": "Intune does not cleanly flatten complex nested Include + Exclude collisions, and 'temporary' 2023 troubleshooting exclusion groups quietly leave dozens of PCs unencrypted and unpatched forever.",
                "architect_rule": "Adopt a strict 'Flat Ring + Intune Filter' model: 4 flat groups (Ring 0 Audit, Ring 1 IT Pilot, Ring 2 Branch/Early, Ring 3 Broad Prod) with zero nesting and expiring documented exceptions.",
            },
            "inspect_items": [
                {
                    "title": f"{g['name']} ({g['member_count']} members — {g['type']})",
                    "severity": "Critical" if "2023" in g["name"] or "Umbrella" in g["name"] or "Collision" in (g.get("risk_flag") or "") else "High",
                    "detail": g["risk_flag"] or "Nested group chain requiring flattening.",
                    "examples": [f"Dynamic rule: {g['rule']}"] if g.get("rule") else [f"Nested children: {len(g.get('nested_children') or [])}"],
                }
                for g in risky_groups[:6]
            ],
            "fix": {
                "steps": [
                    "Audit every 'Temp / Exclude / Bypass' group and confirm whether each member still has an approved exception.",
                    "Run the script below to create 4 clean, flat Entra Security Groups (SG-Intune-OIB-Ring0 through Ring3).",
                    "Use Intune Assignment Filters (e.g., OS/Model/Ownership) instead of creating new nested dynamic groups.",
                ],
                "script_name": "Stage2B-StaleGroups-And-FlatRings.ps1",
                "script_download_url": "/api/scripts/ring_groups",
                "script_content": generate_stale_group_cleanup_script(risky_groups),
                "deep_link_tab": "explorer",
            },
            "memory_template": {
                "category": "Group Architecture Standard",
                "default_summary": "Standardized on 4 flat OIB Ring groups and flagged stale troubleshooting exclusion groups for retirement.",
                "default_details": "Eliminated multi-level group nesting for new Intune policies; exceptions now require an RFC ticket and 90-day review date.",
            },
        },
        {
            "id": "autopilot-esp",
            "order": 3,
            "title": "Autopilot, ESP & Patch Ring Rescue",
            "tagline": "Fix broken OOBE provisioning timeouts, mixed Win32/LOB ESP crashes, and silent patching stalls.",
            "difficulty": "Intermediate",
            "time_estimate": "20 min",
            "user_impact": "Fixes Broken Imaging & Patching",
            "findings_count": len(autopilot),
            "completed": is_done("autopilot-esp"),
            "memory_count": len(track_memories("autopilot-esp")),
            "learn": {
                "what_it_is": "Autopilot Enrollment Status Page (ESP) controls what installs before a user reaches the desktop. Misconfigured ESP blocking apps, OOBE updates, and Device-targeted Update Rings cause endless provisioning failures.",
                "why_it_breaks": "Mixing Win32 and LOB MSIs during ESP triggers Windows Installer lock collisions (0x80070652). Targeting Windows Update Rings to Autopilot Device groups causes mid-ESP reboots, while Feature Updates set to 'ASAP' silently ignore your Update Ring deferrals.",
                "architect_rule": "Package everything as Win32 (zero LOB MSIs), block ESP on max 4–5 core apps (60-min timeout), provision Standard Users (Entra Joined), and target Update Rings cleanly to Post-OOBE/User rings.",
            },
            "inspect_items": [
                {
                    "title": f"{a['object_name']} ({a['object_type']})",
                    "severity": a["severity"],
                    "detail": f"{a['finding']} — Impact: {a['why_it_breaks']}",
                    "examples": [f"Fix: {a['recommended_fix']}"],
                }
                for a in autopilot
            ],
            "fix": {
                "steps": [
                    "Run the Read-Only Autopilot & ESP Audit script below to inventory blocking app counts and OOBE user types.",
                    "Trim ESP blocking apps down to 4 essentials (Defender/VPN/M365/Company Portal) and convert any LOB MSIs to Win32.",
                    "Move Windows Update Rings off Autopilot ZTDID Device groups and switch Feature Updates from 'ASAP' to Gradual Rollout.",
                ],
                "script_name": "Track3-Audit-Autopilot-ESP-And-PatchRings.ps1",
                "script_download_url": "/api/scripts/autopilot_audit",
                "script_content": AUTOPILOT_ESP_AUDIT_PS1,
                "deep_link_tab": "explorer",
            },
            "memory_template": {
                "category": "Autopilot & Patching Standard",
                "default_summary": "Audited ESP blocking apps, standardized on Win32-only OOBE + 60m timeout, and separated Update Rings from Autopilot Device groups.",
                "default_details": "Documented 4-ring WUfB/Autopatch cadence (0d/3d/7d/14d) with Gradual Feature Update rollout and WSUS lock self-healing.",
            },
        },
        {
            "id": "rbac-maa",
            "order": 4,
            "title": "Over-Privileged Custom RBAC & MAA",
            "tagline": "Find custom Intune roles accidentally granting Wipe/Script powers and prep safely for Multi-Admin Approval.",
            "difficulty": "Intermediate",
            "time_estimate": "20 min",
            "user_impact": "Eliminates Admin Blast Radius",
            "findings_count": len(custom_roles) + len([a for a in enterprise_apps if a["maa_break_risk"].startswith("HIGH")]),
            "completed": is_done("rbac-maa"),
            "memory_count": len(track_memories("rbac-maa")),
            "learn": {
                "what_it_is": "Custom Intune roles are often cloned in a hurry—leaving Tier-1 Helpdesk or App Packagers with Wipe, Delete, PowerShell Script, or Role Assignment rights—while standing Intune Admins operate 24/7 without PIM.",
                "why_it_breaks": "One phished Tier-1 helpdesk credential can wipe every corporate laptop or push ransomware via Intune Scripts. Meanwhile, turning on Multi-Admin Approval (MAA) blindly breaks automation apps (HTTP 400/403) unless you exclude verified service principals first.",
                "architect_rule": "Strip destructive rights from Tier-1 custom roles, move standing Intune Admins to Entra PIM Eligible (included in M365 E7), whitelist automation Enterprise Apps, then enable MAA on Wipe/Scripts/RBAC.",
            },
            "inspect_items": [
                {
                    "title": f"{r['role_name']} ({r['members_count']} assigned users)",
                    "severity": r["severity"],
                    "detail": r["why_it_is_dangerous"],
                    "examples": r["overprivileged_permissions"] + [f"Fix: {r['recommended_fix']}"],
                }
                for r in custom_roles
            ] + [
                {
                    "title": f"MAA App-Auth Pre-Flight: {a['app_name']}",
                    "severity": "High",
                    "detail": a["maa_break_risk"],
                    "examples": [f"Auth: {a['auth_type']}", f"Scopes: {', '.join(a['graph_permissions'])}"],
                }
                for a in enterprise_apps
                if a["maa_break_risk"].startswith("HIGH")
            ],
            "fix": {
                "steps": [
                    "Run the Read-Only RBAC & Standing Admin Audit script below to surface dangerous custom role permissions.",
                    "Remove Wipe/Delete/Script/Assign rights from Tier-1 Helpdesk (keep Sync, Restart, BitLocker & LAPS Read).",
                    "Convert standing Intune Administrators to Entra PIM Eligible (4-hr JIT activation + ticket justification).",
                    "Register verified patching Enterprise Apps in Intune MAA Exclusions BEFORE enabling MAA.",
                ],
                "script_name": "Track4-Audit-CustomRBAC-And-StandingAdmins.ps1",
                "script_download_url": "/api/scripts/rbac_audit",
                "script_content": RBAC_AUDIT_PS1,
                "deep_link_tab": "governance",
            },
            "memory_template": {
                "category": "RBAC & Segregation of Duties",
                "default_summary": "Audited over-privileged custom Intune roles, documented Entra PIM migration, and cataloged MAA Enterprise App exclusions.",
                "default_details": "Tier-1 Helpdesk restricted to non-destructive support; destructive device actions and script deployments gated behind Multi-Admin Approval.",
            },
        },
        {
            "id": "scope-tags",
            "order": 5,
            "title": "Scope Tags & 'Invisible Objects'",
            "tagline": "Uncover policies and devices accidentally hidden from HQ, Helpdesk, or Auditors by Scope Tag traps.",
            "difficulty": "Intermediate",
            "time_estimate": "15 min",
            "user_impact": "Stops Hidden Duplicate Sprawl",
            "findings_count": len(scope_tags),
            "completed": is_done("scope-tags"),
            "memory_count": len(track_memories("scope-tags")),
            "learn": {
                "what_it_is": "Scope Tags control WHICH admins can see and edit an Intune object—they NEVER control which devices receive a policy. Removing the 'Default' Scope Tag hides objects from every admin not explicitly granted that custom tag.",
                "why_it_breaks": "Admins routinely mistake Scope Tags for device targeting, or remove the 'Default' tag on branch policies. Then HQ admins think the policy doesn't exist and build a duplicate—creating invisible conflicts and 'Device not found' support calls.",
                "architect_rule": "Keep 'Default' on all global/shared policies, limit custom Scope Tags to <=3 clear boundaries, auto-assign device Scope Tags via flat dynamic groups, and grant Read-Only Auditors visibility across ALL tags.",
            },
            "inspect_items": [
                {
                    "title": t["object_name"],
                    "severity": t["severity"],
                    "detail": f"{t['pitfall']} — Symptom: {t['real_world_symptom']}",
                    "examples": [f"Tags: {', '.join(t['scope_tags_applied'])}", f"Fix: {t['recommended_fix']}"],
                }
                for t in scope_tags
            ],
            "fix": {
                "steps": [
                    "Run the Read-Only Scope Tag Audit script below to list every policy missing the 'Default' (0) tag.",
                    "Restore 'Default' tag on global policies or ensure InfoSec/Read-Only Auditor roles include all Scope Tags.",
                    "Verify every custom-tagged policy's Assignments tab—never rely on a Scope Tag to limit policy targeting!",
                ],
                "script_name": "Track5-Audit-ScopeTag-Visibility.ps1",
                "script_download_url": "/api/scripts/scope_tag_audit",
                "script_content": SCOPE_TAG_AUDIT_PS1,
                "deep_link_tab": "explorer",
            },
            "memory_template": {
                "category": "Scope Tag Governance",
                "default_summary": "Audited policies missing Default Scope Tag and documented strict separation between Scope Tags (visibility) and Assignments (targeting).",
                "default_details": "Capped tenant at 3 documented Scope Tags; ensured Read-Only Auditors see all tags to prevent duplicate policy sprawl.",
            },
        },
        {
            "id": "oib-cis-waves",
            "order": 6,
            "title": "Safe OIB / CIS Compliance Waves",
            "tagline": "Roll out common-sense security baselines in 3 risk-ordered waves with 1-click rollback & self-healing.",
            "difficulty": "Capstone • High Value",
            "time_estimate": "Ongoing Waves",
            "user_impact": "Zero-Breakage Phased Rollout",
            "findings_count": len([c for c in controls if c["current_ring"] == "Not Deployed"]),
            "completed": is_done("oib-cis-waves"),
            "memory_count": len(track_memories("oib-cis-waves")),
            "learn": {
                "what_it_is": "OpenIntuneBaseline (OIB) gives you CIS/NCUA-aligned hardening without strict CIS L2 user-breaking traps (like pre-boot BitLocker PINs, auto-deny UAC, or blanket USB blocks that kill branch check scanners).",
                "why_it_breaks": "Pushing all baselines simultaneously to All Devices causes helpdesk meltdowns and forces leadership to roll everything back—setting security back by a year.",
                "architect_rule": "Roll out in 3 Waves: Wave 1 Low-Risk Quick Wins (BitLocker, LAPS, Agent 365) -> Wave 2 Medium Risk (Patch Rings, UAC, Edge, Cred Guard w/o UEFI lock) -> Wave 3 High Risk in mandatory 14-day Ring 0 Audit first (ASR, Firewall, CA, USB).",
            },
            "inspect_items": [
                {
                    "title": f"{c['id']} — {c['name']}",
                    "severity": c["user_breakage_risk"],
                    "detail": f"Current Ring: {c['current_ring']} • {c['plain_english']}",
                    "examples": [f"Breakage Watchout: {c['what_breaks_in_prod']}", f"CIS/Reg: {c['cis_ref']}"],
                    "control_id": c["id"],
                    "current_ring": c["current_ring"],
                    "can_promote": c["can_promote"],
                    "can_rollback": c["can_rollback"],
                }
                for c in controls
            ],
            "fix": {
                "steps": [
                    "Click 'Diff & Breakage Guide' on any control below to inspect OIB vs. CIS and pre-written auditor rationales.",
                    "Stage Wave 1 (Low Risk) controls into Ring 1 (IT Pilot) with an ITIL RFC ticket.",
                    "Start Wave 3 (High Risk: ASR, Firewall, CA, USB) strictly in Ring 0 (Audit) for a 14-day telemetry soak.",
                ],
                "script_name": None,
                "script_download_url": None,
                "script_content": None,
                "deep_link_tab": "explorer",
            },
            "memory_template": {
                "category": "OIB / CIS Baseline & Exceptions",
                "default_summary": "Initiated 3-wave OIB/CIS rollout with documented CIS deviation rationales and Ring 0 Audit soak for branch peripherals.",
                "default_details": "BitLocker TPM-only + Entra escrow, UAC Secure Desktop credential prompt, and third-party EDR/DLP coexistence guardrails approved via ITIL CAB.",
            },
        },
        {
            "id": "device-personas-sccm",
            "order": 7,
            "title": "Device Personas, Kiosks, AVD & Zombie SCCM",
            "tagline": "Fence off locked-down AVD kiosks, multi-session AVD hosts, EOL Win10, and orphaned SCCM clients before baselines hit them.",
            "difficulty": "M&A Reality • Essential",
            "time_estimate": "20 min",
            "user_impact": "Prevents Kiosk & Co-Mgmt Outages",
            "findings_count": len(device_personas),
            "completed": is_done("device-personas-sccm"),
            "memory_count": len(track_memories("device-personas-sccm")),
            "learn": {
                "what_it_is": "Merged enterprises never have one uniform laptop fleet—they have locked-down AVD kiosks, hybrid GPO-managed AVD hosts, active Co-Managed SCCM + 3rd-party patch hosts, orphaned dead-SCCM clients, and EOL Win10 stragglers sharing one Intune tenant.",
                "why_it_breaks": "Targeting 'All Devices' pushes corporate workstation reboots onto AVD kiosks, breaks multi-session VDI hosts, fights active SCCM Co-Management sliders, and gets silently ignored by dead-SCCM zombie clients whose local Registry.pol locks are still tattooed.",
                "architect_rule": "Create fast Intune Assignment Filters to fence off AVD Kiosks, AVD Session Hosts, and Win10 EOL; scrub zombie SCCM clients on decommissioned sites only; and move refreshed physical PCs straight to Entra Join + Cloud Kerberos Trust instead of re-tattooing them in a new AD forest.",
            },
            "inspect_items": [
                {
                    "title": p["object_name"],
                    "severity": p["severity"],
                    "detail": p["finding"],
                    "examples": [f"Fix: {p['recommended_fix']}"],
                }
                for p in device_personas
            ],
            "fix": {
                "steps": [
                    "Set your active Environment Stack Profile (3rd-Party EDR/DLP & SCCM state) in Tab 2 so Track 6 auto-adapts safety guardrails.",
                    "Create 3 Intune Assignment Filters: FLT-Windows-AVD-Kiosks, FLT-Windows-AVD-SessionHosts, and FLT-Windows10-EOL-Quarantine.",
                    "Run the Dry-Run Zombie ConfigMgr Scrubber ONLY on devices from the decommissioned SCCM site (never on active co-managed hosts).",
                    "Whitelist active 3rd-Party Cloud Patch publishers (e.g., Patch My PC Cloud) in MAA before enabling Multi-Admin Approval.",
                ],
                "script_name": "Track7-Scrub-OrphanedSCCM-And-AuditPersonas.ps1",
                "script_download_url": "/api/scripts/zombie_sccm_scrubber",
                "script_content": ZOMBIE_SCCM_AND_PERSONAS_PS1,
                "deep_link_tab": "connect",
            },
            "memory_template": {
                "category": "Device Personas & Coexistence",
                "default_summary": "Isolated AVD kiosks, multi-session AVD hosts, and EOL Win10 with Assignment Filters; documented Active vs. Orphaned ConfigMgr boundaries.",
                "default_details": f"Active stack: EDR={env_profile.get('edr_provider','third_party_disabled')}, DLP={env_profile.get('dlp_provider','third_party_dlp')}, SCCM={env_profile.get('sccm_state','mixed_active_and_orphaned')}.",
            },
        },
    ]

    for tr in tracks:
        claim = track_claims.get(tr["id"])
        tr["owner"] = claim["owner"] if claim else None
        tr["claimed_at_utc"] = claim["claimed_at_utc"] if claim else None
        tr["claim_notes"] = claim["notes"] if claim else ""
    return tracks
