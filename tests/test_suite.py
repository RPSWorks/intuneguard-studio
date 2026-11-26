"""End-to-End Automated Verification Suite for IntuneGuard Studio."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import IntuneGuardRouter, create_runtime
from backend.config import AppConfig
from backend.graph_adapter import EgressPolicyViolation, LiveGraphAdapter


class TestIntuneGuardStudio(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmp.name)
        self.cfg = AppConfig(
            mode="synthetic",
            host="127.0.0.1",
            port=0,
            require_rfc_for_writes=True,
            db_path=tmp_path / "test_audit.db",
            jsonl_log_path=tmp_path / "test_audit.jsonl",
        )
        self.cfg, self.engine, self.mcp = create_runtime(self.cfg)
        self.router = IntuneGuardRouter(self.cfg, self.engine, self.mcp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _get_json(self, path: str) -> dict:
        status, headers, raw = self.router.dispatch("GET", path)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        return json.loads(raw.decode("utf-8"))

    def _post_json(self, path: str, body: dict) -> tuple[int, dict]:
        status, _headers, raw = self.router.dispatch("POST", path, json.dumps(body).encode("utf-8"))
        return status, json.loads(raw.decode("utf-8"))

    def test_01_sprawl_scale_and_nested_groups(self) -> None:
        ov = self._get_json("/api/overview")
        self.assertEqual(ov["kpis"]["total_policies"], 418)
        self.assertGreater(ov["kpis"]["conflicting_policies"], 20)
        self.assertGreater(ov["kpis"]["nested_group_chains"], 3)
        self.assertFalse(ov["e7_compatibility"]["intune_suite_required"])
        self.assertTrue(ov["audit_chain_integrity"]["valid"])

        gc = self._get_json("/api/groups/conflicts")
        max_depth = max(ch["nesting_depth"] for ch in gc["nested_chains"])
        self.assertGreaterEqual(max_depth, 3)

        # Verify paginated search over 418 policies
        p = self._get_json("/api/policies?status=conflict&page=1&page_size=10")
        self.assertGreater(p["total"], 20)
        self.assertEqual(len(p["items"]), 10)

    def test_02_strict_egress_allowlist(self) -> None:
        LiveGraphAdapter._enforce_allowlist("https://graph.microsoft.com/v1.0/groups")
        LiveGraphAdapter._enforce_allowlist("https://login.microsoftonline.com/tenant/oauth2/v2.0/token")
        with self.assertRaises(EgressPolicyViolation):
            LiveGraphAdapter._enforce_allowlist("https://exfil.attacker.example/collect")

    def test_03_itil_rfc_gate_promote_rollback_and_tamper_detection(self) -> None:
        # Missing RFC must be blocked with HTTP 400
        code, err = self._post_json(
            "/api/rollout/transition",
            {"control_id": "OIB-ENC-001", "action": "promote", "rfc_ticket": ""},
        )
        self.assertEqual(code, 400)
        self.assertIn("RFC", err["error"])

        # Valid RFC promotes Ring 0 -> Ring 1 -> Rollback to Ring 0
        code, res1 = self._post_json(
            "/api/rollout/transition",
            {"control_id": "OIB-ENC-001", "action": "promote", "rfc_ticket": "CHG-2026-2001", "actor": "tester@corp.local"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(res1["rollout"]["current_ring"], "Ring 0 (Audit)")

        code, res2 = self._post_json(
            "/api/rollout/transition",
            {"control_id": "OIB-ENC-001", "action": "promote", "rfc_ticket": "CHG-2026-2002", "actor": "tester@corp.local"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(res2["rollout"]["current_ring"], "Ring 1 (IT Pilot)")

        code, res3 = self._post_json(
            "/api/rollout/transition",
            {"control_id": "OIB-ENC-001", "action": "rollback", "rfc_ticket": "CHG-2026-2003", "actor": "tester@corp.local"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(res3["rollout"]["current_ring"], "Ring 0 (Audit)")

        audit = self._get_json("/api/audit")
        self.assertTrue(audit["chain_integrity"]["valid"])
        self.assertGreaterEqual(audit["chain_integrity"]["checked"], 4)

        # Simulate DB tampering and prove SHA-256 hash chain catches it
        conn = sqlite3.connect(str(self.cfg.db_path))
        try:
            conn.execute("UPDATE audit_events SET rfc_ticket = 'FAKE-TAMPER' WHERE id = 2")
            conn.commit()
        finally:
            conn.close()
        tampered = self.engine.audit.verify_chain()
        self.assertFalse(tampered["valid"])

    def test_04_mcp_http_and_human_in_the_loop_approval(self) -> None:
        code, init_resp = self._post_json("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(code, 200)
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "intuneguard-studio-mcp")

        code, list_resp = self._post_json("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(code, 200)
        self.assertEqual(len(list_resp["result"]["tools"]), 9)

        # Submit write proposal via MCP -> must queue for human approval, NOT auto-promote
        code, prop_resp = self._post_json(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "propose_policy_change",
                    "arguments": {
                        "control_id": "OIB-DEF-002",
                        "target_ring": "Ring 0 (Audit)",
                        "rfc_ticket": "CHG-2026-3001",
                        "justification": "14-day ASR audit soak for branch peripherals",
                        "actor": "copilot-agent@corp.local",
                    },
                },
            },
        )
        self.assertEqual(code, 200)
        prop_id = prop_resp["result"]["structuredContent"]["proposal"]["proposal_id"]

        baseline_before = self._get_json("/api/baseline")
        asr_before = next(c for c in baseline_before["controls"] if c["id"] == "OIB-DEF-002")
        self.assertEqual(asr_before["current_ring"], "Not Deployed")

        # Human CAB approves proposal
        code, approved = self._post_json(
            "/api/proposals/resolve",
            {"proposal_id": prop_id, "decision": "APPROVED", "reviewer": "cab@corp.local"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(approved["rollout"]["rollout"]["current_ring"], "Ring 0 (Audit)")

    def test_05_static_spa_and_auditor_reports(self) -> None:
        for path, expected in [
            ("/", "IntuneGuard Studio"),
            ("/styles.css", "--accent"),
            ("/app.js", "refreshAll"),
            ("/api/report/html", "Executive As-Built"),
            ("/api/report/markdown", "# IntuneGuard Studio"),
        ]:
            status, _headers, raw = self.router.dispatch("GET", path)
            self.assertEqual(status, 200)
            self.assertIn(expected, raw.decode("utf-8"))

        # Confirm logo assets serve cleanly and path traversal is blocked
        for asset in ("/assets/logo.png", "/assets/favicon.png"):
            status, headers, raw = self.router.dispatch("GET", asset)
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "image/png")
            self.assertTrue(raw.startswith(b"\x89PNG"))

        status, _, _ = self.router.dispatch("GET", "/../app.py")
        self.assertEqual(status, 404)

    def test_06_stdio_mcp_server_subprocess(self) -> None:
        env = dict(**os.environ, INTUNEGUARD_DATA_DIR=self._tmp.name)
        proc = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "mcp_server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            reqs = [
                json.dumps({"jsonrpc": "2.0", "id": 10, "method": "initialize"}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": {
                            "name": "generate_self_healing_remediation",
                            "arguments": {"control_id": "OIB-UPD-007"},
                        },
                    }
                ),
            ]
            out, _err = proc.communicate("\n".join(reqs) + "\n", timeout=10)
            lines = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["id"], 10)
            self.assertIn("Remediate-WUfB-StaleWSUSLocks", lines[1]["result"]["content"][0]["text"])
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_07_guided_playbook_scripts_and_offline_tenant_import(self) -> None:
        pb = self._get_json("/api/playbook")
        self.assertEqual(len(pb["stages"]), 5)
        self.assertEqual(len(pb["stages"][3]["waves"]), 3)
        self.assertIn("export_snapshot", pb["scripts"])

        # Verify all 4 PowerShell script download endpoints
        for key, marker in [
            ("export_snapshot", "Connect-MgGraph"),
            ("app_registration", "New-SelfSignedCertificate"),
            ("orphan_cleanup", "IntuneGuard_Orphan_Backups"),
            ("ring_groups", "SG-Intune-OIB-Ring0-Audit"),
        ]:
            status, headers, raw = self.router.dispatch("GET", f"/api/scripts/{key}")
            self.assertEqual(status, 200)
            self.assertIn(".ps1", headers.get("Content-Disposition", ""))
            self.assertIn(marker, raw.decode("utf-8"))

        # Mark a playbook task complete and verify progress persists
        code, res = self._post_json("/api/playbook/task", {"task_id": "s1-review-e7", "completed": True})
        self.assertEqual(code, 200)
        self.assertTrue(res["completed"])
        pb2 = self._get_json("/api/playbook")
        self.assertGreaterEqual(pb2["completed_tasks"], 1)

        # Upload a realistic offline Graph JSON snapshot and verify automatic analysis
        sample_export = {
            "tenant_name": "Acme Credit Union",
            "tenant_id": "11111111-2222-3333-4444-555555555555",
            "windows_devices_count": 320,
            "groups": [
                {"id": "g1", "displayName": "DYN-Win11-All", "groupTypes": ["DynamicMembership"]},
                {"id": "g2", "displayName": "SG-Temp-Exclude-Legacy", "groupTypes": []},
            ],
            "configuration_policies": [
                {
                    "id": "p1",
                    "name": "BitLocker Standard",
                    "lastModifiedDateTime": "2026-11-01T12:00:00Z",
                    "assignments": [
                        {"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g1"}},
                        {"target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g2"}},
                    ],
                },
                {
                    "id": "p2",
                    "name": "Orphaned Test Policy",
                    "lastModifiedDateTime": "2025-05-01T12:00:00Z",
                    "assignments": [],
                },
            ],
            "device_configurations": [],
            "compliance_policies": [],
            "audit_events": [
                {"activityDateTime": "2026-11-20T10:00:00Z", "displayName": "BitLocker Standard", "activity": "Patch Policy"}
            ],
        }
        code, imp_ov = self._post_json("/api/tenant/import", sample_export)
        self.assertEqual(code, 200)
        self.assertEqual(imp_ov["tenant"]["mode"], "imported")
        self.assertEqual(imp_ov["kpis"]["total_policies"], 2)
        self.assertEqual(imp_ov["kpis"]["orphaned_policies"], 1)
        self.assertEqual(imp_ov["kpis"]["conflicting_policies"], 1)

        # Reset back to 418-policy synthetic sandbox
        code, reset_ov = self._post_json("/api/tenant/reset", {})
        self.assertEqual(code, 200)
        self.assertEqual(reset_ov["tenant"]["mode"], "synthetic")
        self.assertEqual(reset_ov["kpis"]["total_policies"], 418)

    def test_08_six_learning_tracks_and_tenant_context_memory_mcp(self) -> None:
        td = self._get_json("/api/tracks")
        self.assertEqual(td["total_tracks"], 7)
        track_ids = [t["id"] for t in td["tracks"]]
        self.assertEqual(
            track_ids,
            [
                "policy-sprawl",
                "nested-groups",
                "autopilot-esp",
                "rbac-maa",
                "scope-tags",
                "oib-cis-waves",
                "device-personas-sccm",
            ],
        )

        # Verify new track-specific PowerShell audit scripts download cleanly
        for key, marker in [
            ("autopilot_audit", "EnrollmentCompletionPage"),
            ("rbac_audit", "roleDefinitions"),
            ("scope_tag_audit", "roleScopeTags"),
            ("zombie_sccm_scrubber", "FLT-Windows-AVD-Kiosks"),
        ]:
            status, headers, raw = self.router.dispatch("GET", f"/api/scripts/{key}")
            self.assertEqual(status, 200)
            self.assertIn(".ps1", headers.get("Content-Disposition", ""))
            self.assertIn(marker, raw.decode("utf-8"))

        # Verify dynamic Environment Stack Profile guardrails (3rd-party EDR disables Defender ASR & warns CA)
        env_default = self._get_json("/api/environment")
        self.assertEqual(env_default["edr_provider"], "third_party_disabled")
        base_3p = self._get_json("/api/baseline")
        asr_3p = next(c for c in base_3p["controls"] if c["id"] == "OIB-DEF-002")
        self.assertIn("3rd-Party EDR", asr_3p["diff_status"])

        # Switch profile to native Microsoft Defender and confirm guardrail clears
        code, updated_env = self._post_json("/api/environment", {"edr_provider": "defender", "presentation_mode": "ai_mcp"})
        self.assertEqual(code, 200)
        self.assertEqual(updated_env["edr_provider"], "defender")
        base_def = self._get_json("/api/baseline")
        asr_def = next(c for c in base_def["controls"] if c["id"] == "OIB-DEF-002")
        self.assertNotIn("Skip ASR", asr_def["diff_status"])

        # Confirm Light/Dark theme CSS variables and topbar toggles exist
        status, _, css_raw = self.router.dispatch("GET", "/styles.css")
        self.assertEqual(status, 200)
        self.assertIn('[data-theme="light"]', css_raw.decode("utf-8"))

        # Record a Tenant Context Memory for Scope Tags & mark track mastered
        code, mem = self._post_json(
            "/api/memory",
            {
                "track_id": "scope-tags",
                "category": "Scope Tag Governance",
                "summary": "Standardized on Default + Region-West + Branch-Ops tags only.",
                "details": "Auditors granted All Scope Tags read visibility to stop duplicate sprawl.",
                "mark_track_complete": True,
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(mem["memory_id"].startswith("MEM-"))

        # Confirm mastery incremented & MCP tool serves the learned tenant memory
        td2 = self._get_json("/api/tracks")
        self.assertEqual(td2["completed_tracks"], 1)
        self.assertEqual(td2["memory_entries_count"], 1)

        code, mcp_mem = self._post_json(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "get_tenant_context_memory", "arguments": {"track_id": "scope-tags"}},
            },
        )
        self.assertEqual(code, 200)
        sc = mcp_mem["result"]["structuredContent"]
        self.assertIn("scope-tags", sc["completed_tracks"])
        self.assertEqual(len(sc["memories"]), 1)
        self.assertIn("Region-West", sc["memories"][0]["summary"])

    def test_09_gpo_xml_parser_and_xxe_blocking(self) -> None:
        sample_gpmc_xml = """<?xml version="1.0" encoding="utf-16"?>
        <report xmlns="http://www.microsoft.com/GroupPolicy/Settings">
          <GPO>
            <Name>Legacy WSUS and LAPS Policy</Name>
            <Computer>
              <ExtensionData>
                <Setting>UseWUServer = 1; WUServer = http://wsus.internal:8530</Setting>
                <Setting>AdmPwdEnabled = 1</Setting>
              </ExtensionData>
            </Computer>
          </GPO>
          <GPO>
            <Name>Legacy BitLocker AES128 GPO</Name>
            <Computer>
              <ExtensionData>
                <Setting>EncryptionMethodWithXtsOs = 3</Setting>
              </ExtensionData>
            </Computer>
          </GPO>
        </report>"""

        code, res = self._post_json("/api/gpo/import", {"xml": sample_gpmc_xml, "actor": "auditor@corp.local"})
        self.assertEqual(code, 200)
        self.assertEqual(res["gpos_scanned"], 2)
        self.assertGreaterEqual(res["collisions_found"], 3)
        keys = {g["setting_key"] for g in res["tattooed_gpos"]}
        self.assertIn("wufb_patching_rings_oobe_safe", keys)
        self.assertIn("windows_laps_entra_rotation", keys)
        self.assertIn("bitlocker_os_xts_aes256_escrow", keys)

        # Confirm XXE / DOCTYPE payloads are strictly blocked with HTTP 400
        xxe_xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GPO><Name>&xxe;</Name></GPO>'
        code, err = self._post_json("/api/gpo/import", {"xml": xxe_xml})
        self.assertEqual(code, 400)
        self.assertIn("XXE", err["error"])

    def test_10_track_claims_outage_backtrack_and_http_hardening(self) -> None:
        # Claim & verify owner on Track 4
        code, claim = self._post_json(
            "/api/tracks/claim",
            {"track_id": "rbac-maa", "owner": "alex@corp.local", "notes": "Auditing Tier-1 custom roles"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(claim["owner"], "alex@corp.local")
        td = self._get_json("/api/tracks")
        tr4 = next(t for t in td["tracks"] if t["id"] == "rbac-maa")
        self.assertEqual(tr4["owner"], "alex@corp.local")

        # Release claim
        code, rel = self._post_json("/api/tracks/release", {"track_id": "rbac-maa", "actor": "alex@corp.local"})
        self.assertEqual(code, 200)
        self.assertTrue(rel["released"])

        # Promote BitLocker control, then backtrack 'bitlocker' via REST & MCP
        code, _ = self._post_json(
            "/api/rollout/transition",
            {"control_id": "OIB-ENC-001", "action": "promote", "rfc_ticket": "CHG-2026-9901", "actor": "alex@corp.local"},
        )
        self.assertEqual(code, 200)

        bt = self._get_json("/api/backtrack?q=bitlocker")
        self.assertGreaterEqual(len(bt["rollback_candidates"]), 1)
        self.assertEqual(bt["rollback_candidates"][0]["control_id"], "OIB-ENC-001")

        code, mcp_bt = self._post_json(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {"name": "backtrack_outage_timeline", "arguments": {"symptom": "bitlocker"}},
            },
        )
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(mcp_bt["result"]["structuredContent"]["rollback_candidates"]), 1)

        # HTTP hardening checks: CSP header, invalid JSON -> 400, bad query int -> 400
        status, headers, _ = self.router.dispatch("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

        status, _, raw = self.router.dispatch("POST", "/api/environment", b"{not valid json")
        self.assertEqual(status, 400)
        self.assertIn("Invalid JSON", raw.decode("utf-8"))

        status, _, raw = self.router.dispatch("GET", "/api/policies?page=notanumber")
        self.assertEqual(status, 400)
        self.assertIn("integer", raw.decode("utf-8"))

    def test_11_apim_gateway_openapi_and_sharepoint_kb(self) -> None:
        # Verify OpenAPI 3.1 contract for Azure APIM import
        spec = self._get_json("/api/openapi.json")
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/mcp", spec["paths"])
        self.assertIn("/api/report/sharepoint-kb", spec["paths"])

        # Verify SharePoint Agent / Agent Builder Knowledge Base export
        status, headers, raw = self.router.dispatch("GET", "/api/report/sharepoint-kb")
        self.assertEqual(status, 200)
        self.assertIn("IntuneGuard_SharePoint_Agent_KB.md", headers.get("Content-Disposition", ""))
        kb_text = raw.decode("utf-8")
        self.assertIn("SharePoint Agents", kb_text)
        self.assertIn("Coexistence Guardrails", kb_text)

        # Verify APIM AI Gateway key enforcement & correlation ID echoing on /mcp
        tmp_path = Path(self._tmp.name)
        apim_cfg = AppConfig(
            mode="synthetic",
            apim_gateway_key="test-apim-secret-key",
            db_path=tmp_path / "apim_audit.db",
            jsonl_log_path=tmp_path / "apim_audit.jsonl",
        )
        apim_cfg, apim_eng, apim_mcp = create_runtime(apim_cfg)
        apim_router = IntuneGuardRouter(apim_cfg, apim_eng, apim_mcp)

        mcp_body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode("utf-8")
        # Missing key -> 401 Unauthorized
        code, _, _ = apim_router.dispatch("POST", "/mcp", mcp_body)
        self.assertEqual(code, 401)

        # Valid APIM subscription key + Entra caller + Correlation ID -> 200 OK
        code, resp_hdrs, _ = apim_router.dispatch(
            "POST",
            "/mcp",
            mcp_body,
            request_headers={
                "Ocp-Apim-Subscription-Key": "test-apim-secret-key",
                "X-MS-CLIENT-PRINCIPAL-NAME": "architect@corp.local",
                "X-Apim-Correlation-Id": "corr-998877",
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(resp_hdrs.get("X-Apim-Correlation-Id"), "corr-998877")


if __name__ == "__main__":
    unittest.main()
