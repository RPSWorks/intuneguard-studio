"""Model Context Protocol (MCP) Tool Registry & JSON-RPC 2.0 Dispatcher.

Shared between:
- mcp_server.py (stdio transport for VS Code / GitHub Copilot, Claude Desktop, or local LLMs)
- app.py (/mcp HTTP JSON-RPC 2.0 endpoint designed to sit behind Azure API Management (APIM) AI Gateway
  for Enterprise MCP Platforms, Microsoft Foundry, and Copilot Agent Builder)

Enforces strict separation of Read-Only inspection tools vs. Human-in-the-Loop
ITIL RFC-gated write proposals.
"""
from __future__ import annotations

import json
from typing import Any

from backend import __version__
from backend.analyzer import IntuneGuardEngine
from backend.baseline_catalog import RING_METADATA, RING_ORDER, get_control_by_id

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "audit_tenant_sprawl",
        "description": (
            "Read-only audit of the Intune tenant returning policy sprawl metrics across 400+ policies, "
            "conflicting/duplicate/orphaned policy counts, nested group traps, tattooed GPOs, "
            "unapproved portal edits, and M365 E7 licensing compatibility."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "evaluate_oib_cis_control",
        "description": (
            "Inspects a specific OpenIntuneBaseline (OIB) vs CIS v5.0.0 control (or lists all controls if control_id is omitted), "
            "returning plain-English impact, end-user breakage warnings, auditor deviation rationale, "
            "conflicting tenant policies/GPOs, and current rollout ring."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {
                    "type": "string",
                    "description": "Optional control ID such as OIB-ENC-001, OIB-DEF-002, OIB-UPD-007. Omit to summarize all 12 controls.",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "resolve_nested_group_conflicts",
        "description": (
            "Resolves multi-level nested dynamic and static Entra ID group chains, exposing include/exclude collisions, "
            "stale troubleshooting exclusion groups, and tattooed on-prem AD GPO overrides."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "generate_self_healing_remediation",
        "description": (
            "Generates ready-to-deploy Microsoft Intune Proactive Remediation PowerShell scripts "
            "(Detect.ps1 and Remediate.ps1) for self-healing a specific OIB/CIS control (natively licensed in M365 E7)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {
                    "type": "string",
                    "description": "Control ID (e.g., OIB-ENC-001, OIB-UPD-007, OIB-NET-005).",
                }
            },
            "required": ["control_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "build_phased_ring_plan",
        "description": (
            "Builds a zero-disruption 4-ring rollout plan (Ring 0 Audit -> Ring 1 IT Pilot -> Ring 2 Branch/Early -> Ring 3 Broad Prod) "
            "with Entra ID security group names, soak durations, and rollback guardrails for a given control."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {
                    "type": "string",
                    "description": "Control ID (e.g., OIB-DEF-002).",
                }
            },
            "required": ["control_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "propose_policy_change",
        "description": (
            "GOVERNED WRITE GATE (Human-in-the-Loop): Submits a formal ITIL RFC-linked rollout proposal "
            "for human approval inside IntuneGuard Studio. Never mutates production Intune directly without human sign-off."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {"type": "string", "description": "Target baseline control ID (e.g., OIB-ENC-001)."},
                "target_ring": {
                    "type": "string",
                    "enum": RING_ORDER,
                    "description": "Desired target rollout ring.",
                },
                "rfc_ticket": {"type": "string", "description": "Mandatory ITIL RFC / Change Ticket ID (e.g., CHG-2026-1099)."},
                "justification": {"type": "string", "description": "Change justification and risk mitigation notes."},
                "actor": {"type": "string", "description": "Requesting agent or engineer identity."},
            },
            "required": ["control_id", "target_ring", "rfc_ticket", "justification"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_itil_audit_chain",
        "description": (
            "Verifies the SHA-256 cryptographic hash chain of the local ITIL audit trail and returns recent governance events."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of recent events to include (default 10)."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_tenant_context_memory",
        "description": (
            "Retrieves accumulated Tenant Context Memory (completed Guided Tracks, documented RBAC/Scope Tag/Autopilot standards, "
            "and approved compliance exceptions) so AI agents adapt accurately to this specific Intune environment over time."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "track_id": {
                    "type": "string",
                    "description": "Optional track filter (policy-sprawl, nested-groups, autopilot-esp, rbac-maa, scope-tags, oib-cis-waves, device-personas-sccm).",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "backtrack_outage_timeline",
        "description": (
            "Correlates a reported endpoint outage or symptom (e.g., 'scanner', 'firewall', 'update', 'kiosk', 'bitlocker') "
            "across unapproved Intune portal edits, SHA-256 ITIL audit events, Tenant Context Memory, and 1-click rollback candidates."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "symptom": {
                    "type": "string",
                    "description": "Symptom keyword or subsystem to correlate (leave empty for full recent timeline).",
                }
            },
            "additionalProperties": False,
        },
    },
]


class MCPDispatcher:
    def __init__(self, engine: IntuneGuardEngine) -> None:
        self.engine = engine

    def handle_jsonrpc(self, request: dict[str, Any]) -> dict[str, Any] | None:
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}

        # Notifications have no id and expect no response in JSON-RPC 2.0
        if req_id is None and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "intuneguard-studio-mcp",
                        "version": __version__,
                    },
                }
            elif method == "tools/list":
                result = {"tools": TOOL_DEFINITIONS}
            elif method == "tools/call":
                tool_name = params.get("name", "")
                tool_args = params.get("arguments") or {}
                payload = self.call_tool(tool_name, tool_args)
                result = {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "structuredContent": payload,
                    "isError": False,
                }
            elif method == "ping":
                result = {}
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": str(exc)},
            }

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "audit_tenant_sprawl":
            data = self.engine.get_tenant_overview()
            self.engine.audit.log_event(
                actor="mcp-client",
                channel="MCP_TOOL",
                action="MCP_AUDIT_TENANT_SPRAWL",
                target_id=data["tenant"]["tenant_id"],
                status="SUCCEEDED",
                rationale="Read-only tenant sprawl audit via MCP.",
            )
            return data

        if name == "evaluate_oib_cis_control":
            controls = self.engine.evaluate_baseline_dry_run()
            cid = (args.get("control_id") or "").strip()
            if cid:
                match = next((c for c in controls if c["id"] == cid), None)
                if not match:
                    raise ValueError(f"Control '{cid}' not found.")
                return match
            return {
                "count": len(controls),
                "controls": [
                    {
                        "id": c["id"],
                        "domain": c["domain"],
                        "name": c["name"],
                        "user_breakage_risk": c["user_breakage_risk"],
                        "current_ring": c["current_ring"],
                        "diff_status": c["diff_status"],
                        "conflict_count": len(c["conflicting_policies"]) + len(c["conflicting_gpos"]),
                    }
                    for c in controls
                ],
            }

        if name == "resolve_nested_group_conflicts":
            return self.engine.get_nested_group_conflicts()

        if name == "generate_self_healing_remediation":
            cid = args.get("control_id", "")
            ctrl = get_control_by_id(cid)
            if not ctrl:
                raise ValueError(f"Unknown control_id: {cid}")
            self.engine.audit.log_event(
                actor="mcp-client",
                channel="MCP_TOOL",
                action="MCP_GENERATE_SELF_HEALING",
                target_id=cid,
                status="SUCCEEDED",
                rationale=f"Generated Proactive Remediation Detect/Remediate scripts for {cid}.",
            )
            return {
                "control_id": ctrl["id"],
                "control_name": ctrl["name"],
                "e7_component": ctrl["e7_component"],
                "remediation_package": ctrl["self_healing"],
            }

        if name == "build_phased_ring_plan":
            cid = args.get("control_id", "")
            ctrl = get_control_by_id(cid)
            if not ctrl:
                raise ValueError(f"Unknown control_id: {cid}")
            return {
                "control_id": ctrl["id"],
                "control_name": ctrl["name"],
                "recommended_start_ring": ctrl["recommended_start_ring"],
                "user_breakage_risk": ctrl["user_breakage_risk"],
                "what_breaks_in_prod": ctrl["what_breaks_in_prod"],
                "rings": [
                    {
                        "ring": r,
                        "entra_group": RING_METADATA[r]["entra_group"],
                        "description": RING_METADATA[r]["description"],
                        "recommended_soak_days": {"Ring 0 (Audit)": 14, "Ring 1 (IT Pilot)": 7, "Ring 2 (Branch/Early)": 7, "Ring 3 (Broad Prod)": 0}.get(r, 0),
                    }
                    for r in RING_ORDER
                    if r != "Not Deployed"
                ],
            }

        if name == "propose_policy_change":
            cid = args.get("control_id", "")
            target_ring = args.get("target_ring", "")
            rfc = (args.get("rfc_ticket") or "").strip()
            just = (args.get("justification") or "").strip()
            actor = (args.get("actor") or "ai-agent@mcp").strip()
            if not get_control_by_id(cid):
                raise ValueError(f"Unknown control_id: {cid}")
            if target_ring not in RING_ORDER:
                raise ValueError(f"Invalid target_ring: {target_ring}")
            if not rfc:
                raise ValueError("rfc_ticket is mandatory for ITIL-governed proposals.")
            proposal = self.engine.audit.create_proposal(
                actor=actor,
                channel="MCP_HUMAN_IN_THE_LOOP",
                control_id=cid,
                target_ring=target_ring,
                rfc_ticket=rfc,
                justification=just or "Submitted via MCP tool",
            )
            return {
                "governance_status": "QUEUED_FOR_HUMAN_APPROVAL",
                "message": "Write action safely blocked pending human CAB/ITIL sign-off in IntuneGuard Studio UI.",
                "proposal": proposal,
            }

        if name == "verify_itil_audit_chain":
            limit = int(args.get("limit") or 10)
            return {
                "chain_integrity": self.engine.audit.verify_chain(),
                "recent_events": self.engine.audit.list_events(limit=limit),
            }

        if name == "get_tenant_context_memory":
            tid = (args.get("track_id") or "").strip() or None
            tracks_info = self.engine.get_guided_tracks()
            return {
                "tenant_name": tracks_info["tenant"]["name"],
                "mastery_pct": tracks_info["mastery_pct"],
                "completed_tracks": [t["id"] for t in tracks_info["tracks"] if t["completed"]],
                "memories": self.engine.audit.list_memories(track_id=tid),
            }

        if name == "backtrack_outage_timeline":
            symptom = str(args.get("symptom") or "")
            return self.engine.backtrack_incident(query=symptom)

        raise ValueError(f"Unknown MCP tool: {name}")
