"""IntuneGuard Studio — Zero-Dependency HTTP Server, REST API & MCP HTTP Endpoint.

Run locally:
    python app.py
Then open http://127.0.0.1:8095
"""
from __future__ import annotations

import json
import mimetypes
import urllib.parse
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from backend import __version__
from backend.analyzer import IntuneGuardEngine
from backend.audit_store import AuditStore
from backend.config import WEB_DIR, AppConfig, load_config
from backend.graph_adapter import build_adapter
from backend.mcp_tools import MCPDispatcher, TOOL_DEFINITIONS

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    ),
}


def _safe_int(raw_val: str, name: str, minimum: int = 1, maximum: int = 500) -> int:
    try:
        parsed = int(raw_val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Query parameter '{name}' must be a valid integer.") from exc
    return max(minimum, min(maximum, parsed))


def create_runtime(config: AppConfig | None = None) -> tuple[AppConfig, IntuneGuardEngine, MCPDispatcher]:
    cfg = config or load_config()
    audit_store = AuditStore(cfg.db_path, cfg.jsonl_log_path)
    adapter = build_adapter(cfg)
    engine = IntuneGuardEngine(cfg, adapter, audit_store)
    mcp = MCPDispatcher(engine)
    return cfg, engine, mcp


class IntuneGuardRouter:
    """Transport-agnostic HTTP router for REST API, static SPA, reports, and /mcp."""

    def __init__(self, config: AppConfig, engine: IntuneGuardEngine, mcp: MCPDispatcher) -> None:
        self.config = config
        self.engine = engine
        self.mcp = mcp

    @staticmethod
    def _json_response(status: int, payload: Any) -> tuple[int, dict[str, str], bytes]:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        headers = {
            **SECURITY_HEADERS,
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(raw)),
        }
        return int(status), headers, raw

    @staticmethod
    def _bytes_response(
        status: int,
        data: bytes,
        content_type: str,
        download_name: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {
            **SECURITY_HEADERS,
            "Content-Type": content_type,
            "Content-Length": str(len(data)),
        }
        if download_name:
            headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return int(status), headers, data

    def _serve_static(self, rel_path: str) -> tuple[int, dict[str, str], bytes]:
        clean = rel_path.lstrip("/") or "index.html"
        target = (WEB_DIR / clean).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            return self._json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        ctype, _ = mimetypes.guess_type(str(target))
        return self._bytes_response(HTTPStatus.OK, target.read_bytes(), ctype or "application/octet-stream")

    def dispatch(
        self,
        method: str,
        raw_path: str,
        body_bytes: bytes = b"",
        request_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urllib.parse.urlparse(raw_path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        hdrs = {k.lower(): v for k, v in (request_headers or {}).items()}
        caller_identity = (
            hdrs.get("x-ms-client-principal-name")
            or hdrs.get("x-forwarded-user")
            or "endpoint-architect@meridianfin.local"
        )
        correlation_id = hdrs.get("x-apim-correlation-id") or hdrs.get("x-correlation-id") or ""

        try:
            if method == "GET":
                if path == "/api/health":
                    return self._json_response(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "version": __version__,
                            "mode": "live" if self.config.is_live else "synthetic",
                            "apim_gateway_auth_enforced": bool(self.config.apim_gateway_key),
                            "audit_chain": self.engine.audit.verify_chain(),
                        },
                    )
                if path == "/api/openapi.json":
                    return self._json_response(
                        HTTPStatus.OK,
                        {
                            "openapi": "3.1.0",
                            "info": {
                                "title": "IntuneGuard Studio Enterprise API & APIM-Governed MCP Backend",
                                "version": __version__,
                                "description": (
                                    "Zero-dependency Intune governance workbench & JSON-RPC 2.0 MCP server "
                                    "designed to sit behind Azure API Management (APIM) AI Gateway with Entra ID auth."
                                ),
                            },
                            "paths": {
                                "/api/health": {"get": {"summary": "Liveness, mode, and SHA-256 audit chain integrity"}},
                                "/api/tracks": {"get": {"summary": "List 7 Guided Learning Tracks with team ownership"}},
                                "/api/backtrack": {"get": {"summary": "Correlate outage symptoms across audit logs & memory"}},
                                "/api/report/sharepoint-kb": {"get": {"summary": "Export SharePoint Agent / Agent Builder Markdown KB"}},
                                "/mcp": {"post": {"summary": "JSON-RPC 2.0 MCP Server endpoint (APIM AI Gateway ready)"}},
                            },
                        },
                    )
                if path == "/api/overview":
                    return self._json_response(HTTPStatus.OK, self.engine.get_tenant_overview())
                if path == "/api/tracks":
                    return self._json_response(HTTPStatus.OK, self.engine.get_guided_tracks())
                if path == "/api/environment":
                    return self._json_response(HTTPStatus.OK, self.engine.audit.get_environment_profile())
                if path == "/api/memory":
                    tid = (qs.get("track_id") or [""])[0] or None
                    return self._json_response(
                        HTTPStatus.OK, {"memories": self.engine.audit.list_memories(track_id=tid)}
                    )
                if path == "/api/playbook":
                    return self._json_response(HTTPStatus.OK, self.engine.get_guided_playbook())
                if path.startswith("/api/scripts/"):
                    script_key = path.split("/api/scripts/", 1)[1].strip("/")
                    scripts = self.engine.get_guided_playbook()["scripts"]
                    if script_key not in scripts:
                        return self._json_response(HTTPStatus.NOT_FOUND, {"error": f"Unknown script: {script_key}"})
                    entry = scripts[script_key]
                    return self._bytes_response(
                        HTTPStatus.OK,
                        entry["content"].encode("utf-8"),
                        "text/plain; charset=utf-8",
                        download_name=entry["filename"],
                    )
                if path == "/api/baseline":
                    return self._json_response(HTTPStatus.OK, {"controls": self.engine.evaluate_baseline_dry_run()})
                if path == "/api/groups/conflicts":
                    return self._json_response(HTTPStatus.OK, self.engine.get_nested_group_conflicts())
                if path == "/api/policies":
                    return self._json_response(
                        HTTPStatus.OK,
                        self.engine.search_policies(
                            query=(qs.get("q") or [""])[0],
                            status=(qs.get("status") or ["all"])[0],
                            category=(qs.get("category") or ["all"])[0],
                            page=_safe_int((qs.get("page") or ["1"])[0], "page", 1, 10000),
                            page_size=_safe_int((qs.get("page_size") or ["25"])[0], "page_size", 1, 200),
                        ),
                    )
                if path == "/api/backtrack":
                    q = (qs.get("q") or [""])[0]
                    limit = _safe_int((qs.get("limit") or ["35"])[0], "limit", 1, 200)
                    return self._json_response(HTTPStatus.OK, self.engine.backtrack_incident(query=q, limit=limit))
                if path == "/api/audit":
                    limit = _safe_int((qs.get("limit") or ["100"])[0], "limit", 1, 500)
                    return self._json_response(
                        HTTPStatus.OK,
                        {
                            "chain_integrity": self.engine.audit.verify_chain(),
                            "events": self.engine.audit.list_events(limit=limit),
                            "proposals": self.engine.audit.list_proposals(),
                        },
                    )
                if path == "/api/mcp/tools":
                    return self._json_response(HTTPStatus.OK, {"tools": TOOL_DEFINITIONS})
                if path == "/api/report/html":
                    doc = self.engine.generate_auditor_report_html().encode("utf-8")
                    return self._bytes_response(
                        HTTPStatus.OK,
                        doc,
                        "text/html; charset=utf-8",
                        download_name="IntuneGuard_AsBuilt_Compliance_Report.html",
                    )
                if path == "/api/report/markdown":
                    doc = self.engine.generate_auditor_report_markdown().encode("utf-8")
                    return self._bytes_response(
                        HTTPStatus.OK,
                        doc,
                        "text/markdown; charset=utf-8",
                        download_name="IntuneGuard_AsBuilt_Compliance_Report.md",
                    )
                if path == "/api/report/sharepoint-kb":
                    doc = self.engine.generate_sharepoint_kb_markdown().encode("utf-8")
                    return self._bytes_response(
                        HTTPStatus.OK,
                        doc,
                        "text/markdown; charset=utf-8",
                        download_name="IntuneGuard_SharePoint_Agent_KB.md",
                    )
                return self._serve_static(path)

            if method == "POST":
                if path == "/api/gpo/import":
                    raw_text = body_bytes.decode("utf-8", errors="replace")
                    actor = "endpoint-architect@local"
                    xml_payload = raw_text
                    if raw_text.lstrip().startswith("{"):
                        try:
                            j = json.loads(raw_text)
                        except json.JSONDecodeError as exc:
                            raise ValueError(f"Invalid JSON payload: {exc}") from exc
                        xml_payload = str(j.get("xml") or "")
                        actor = str(j.get("actor") or actor)
                    parsed = self.engine.import_gpo_xml(xml_payload, actor=actor)
                    return self._json_response(HTTPStatus.OK, parsed)

                try:
                    body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON payload: {exc}") from exc
                if not isinstance(body, dict):
                    raise ValueError("JSON request body must be an object.")

                if path == "/api/tracks/claim":
                    tid = str(body.get("track_id") or "").strip()
                    owner = str(body.get("owner") or "").strip()
                    if not tid or not owner:
                        raise ValueError("track_id and owner are required.")
                    res = self.engine.audit.claim_track(tid, owner, str(body.get("notes") or ""))
                    return self._json_response(HTTPStatus.OK, res)

                if path == "/api/tracks/release":
                    tid = str(body.get("track_id") or "").strip()
                    if not tid:
                        raise ValueError("track_id is required.")
                    res = self.engine.audit.release_track(tid, actor=str(body.get("actor") or "endpoint-architect@local"))
                    return self._json_response(HTTPStatus.OK, res)
                if path == "/api/playbook/task":
                    task_id = str(body.get("task_id") or "").strip()
                    if not task_id:
                        return self._json_response(HTTPStatus.BAD_REQUEST, {"error": "task_id is required"})
                    res = self.engine.audit.set_playbook_task(
                        task_id=task_id,
                        completed=bool(body.get("completed", True)),
                        actor=str(body.get("actor") or "endpoint-architect@meridianfin.local"),
                        notes=str(body.get("notes") or ""),
                    )
                    return self._json_response(HTTPStatus.OK, res)

                if path == "/api/memory":
                    track_id = str(body.get("track_id") or "general").strip()
                    summary = str(body.get("summary") or "").strip()
                    if not summary:
                        return self._json_response(HTTPStatus.BAD_REQUEST, {"error": "summary is required"})
                    mem = self.engine.audit.add_memory(
                        track_id=track_id,
                        category=str(body.get("category") or "Tenant Decision").strip(),
                        summary=summary,
                        details=str(body.get("details") or "").strip(),
                        recorded_by=str(body.get("recorded_by") or "endpoint-architect@meridianfin.local"),
                    )
                    if body.get("mark_track_complete"):
                        self.engine.audit.set_playbook_task(
                            f"track:{track_id}",
                            True,
                            actor=str(body.get("recorded_by") or "endpoint-architect@meridianfin.local"),
                            notes=summary,
                        )
                    return self._json_response(HTTPStatus.OK, mem)

                if path == "/api/tenant/import":
                    overview = self.engine.import_offline_snapshot(
                        body, actor=str(body.get("_actor") or "endpoint-architect@local")
                    )
                    return self._json_response(HTTPStatus.OK, overview)

                if path == "/api/tenant/reset":
                    overview = self.engine.reset_to_default_snapshot()
                    return self._json_response(HTTPStatus.OK, overview)

                if path == "/api/environment":
                    saved = self.engine.audit.save_environment_profile(
                        body, actor=str(body.get("_actor") or "endpoint-architect@local")
                    )
                    return self._json_response(HTTPStatus.OK, saved)

                if path == "/api/rollout/transition":
                    result = self.engine.transition_ring(
                        control_id=body.get("control_id", ""),
                        action=body.get("action", "promote"),
                        rfc_ticket=body.get("rfc_ticket", ""),
                        actor=body.get("actor", "endpoint-architect@meridianfin.local"),
                        channel="WEB_STUDIO",
                        note=body.get("note", ""),
                        target_ring=body.get("target_ring"),
                    )
                    return self._json_response(HTTPStatus.OK, result)

                if path == "/api/proposals/resolve":
                    prop_id = body.get("proposal_id", "")
                    decision = body.get("decision", "").upper()
                    reviewer = body.get("reviewer", "cab-approver@meridianfin.local")
                    if decision not in ("APPROVED", "REJECTED"):
                        return self._json_response(
                            HTTPStatus.BAD_REQUEST, {"error": "decision must be APPROVED or REJECTED"}
                        )
                    resolved = self.engine.audit.resolve_proposal(prop_id, decision, reviewer)
                    if not resolved:
                        return self._json_response(HTTPStatus.NOT_FOUND, {"error": f"Proposal '{prop_id}' not found"})
                    rollout_result = None
                    if decision == "APPROVED":
                        rollout_result = self.engine.transition_ring(
                            control_id=resolved["control_id"],
                            action="promote",
                            target_ring=resolved["target_ring"],
                            rfc_ticket=resolved["rfc_ticket"],
                            actor=reviewer,
                            channel="ITIL_CAB_APPROVAL",
                            note=f"Approved MCP proposal {prop_id}: {resolved['justification']}",
                        )
                    else:
                        self.engine.audit.log_event(
                            actor=reviewer,
                            channel="ITIL_CAB_APPROVAL",
                            action="PROPOSAL_REJECTED",
                            target_id=resolved["control_id"],
                            rfc_ticket=resolved["rfc_ticket"],
                            status="REJECTED",
                            after_state={"proposal_id": prop_id},
                            rationale=body.get("note", "Rejected by CAB reviewer"),
                        )
                    return self._json_response(HTTPStatus.OK, {"proposal": resolved, "rollout": rollout_result})

                if path == "/mcp":
                    # Enforce APIM AI Gateway shared secret/subscription header when configured
                    if self.config.apim_gateway_key:
                        provided = hdrs.get("x-intuneguard-apim-key") or hdrs.get("ocp-apim-subscription-key") or ""
                        if provided != self.config.apim_gateway_key:
                            return self._json_response(
                                HTTPStatus.UNAUTHORIZED,
                                {"error": "Unauthorized: Valid APIM AI Gateway key required for /mcp."},
                            )
                    response = self.mcp.handle_jsonrpc(body)
                    if self.config.json_logs:
                        print(
                            json.dumps(
                                {
                                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                                    "component": "intuneguard-mcp",
                                    "method": body.get("method"),
                                    "tool": (body.get("params") or {}).get("name"),
                                    "caller": caller_identity,
                                    "correlation_id": correlation_id,
                                }
                            )
                        )
                    if response is None:
                        return int(HTTPStatus.NO_CONTENT), SECURITY_HEADERS, b""
                    status_code, resp_hdrs, raw = self._json_response(HTTPStatus.OK, response)
                    if correlation_id:
                        resp_hdrs["X-Apim-Correlation-Id"] = correlation_id
                    return status_code, resp_hdrs, raw

                return self._json_response(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

            return self._json_response(HTTPStatus.METHOD_NOT_ALLOWED, {"error": f"Method {method} not allowed"})
        except ValueError as exc:
            return self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            return self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})


def make_handler(router: IntuneGuardRouter):
    class IntuneGuardHandler(BaseHTTPRequestHandler):
        server_version = f"IntuneGuardStudio/{__version__}"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            print(f"[HTTP] {self.address_string()} - {format % args}")

        def _respond(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(min(length, 10_000_000)) if length > 0 else b""
            hdr_dict = {k: v for k, v in self.headers.items()}
            status, headers, raw = router.dispatch(method, self.path, body, request_headers=hdr_dict)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            self._respond("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._respond("POST")

    return IntuneGuardHandler


def run_server() -> None:
    cfg, engine, mcp = create_runtime()
    router = IntuneGuardRouter(cfg, engine, mcp)
    server = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(router))
    print(f"IntuneGuard Studio v{__version__} running at http://{cfg.host}:{cfg.port}")
    print(
        f"Mode: {'LIVE GRAPH (Read-Only Allowlisted)' if cfg.is_live else 'SYNTHETIC SANDBOX (418 Policies / Zero Egress)'}"
    )
    print(f"MCP HTTP Endpoint: http://{cfg.host}:{cfg.port}/mcp")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down IntuneGuard Studio.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
