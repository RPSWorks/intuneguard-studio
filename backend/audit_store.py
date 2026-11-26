"""Immutable, hash-chained SQLite + JSONL ITIL Audit & Change Control Store.

Every rollout promotion, rollback, RFC proposal, and MCP tool invocation is
recorded with SHA-256 chain hashing so regulated internal audit / NCUA / FFIEC
reviewers can verify tamper-evidence of change history.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class AuditStore:
    def __init__(self, db_path: Path, jsonl_path: Path) -> None:
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_uid TEXT NOT NULL UNIQUE,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    rfc_ticket TEXT,
                    status TEXT NOT NULL,
                    before_json TEXT,
                    after_json TEXT,
                    rationale TEXT,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rollout_state (
                    control_id TEXT PRIMARY KEY,
                    current_ring TEXT NOT NULL,
                    previous_ring TEXT,
                    last_rfc TEXT,
                    updated_by TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    history_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pending_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    created_at_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    target_ring TEXT NOT NULL,
                    rfc_ticket TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reviewed_by TEXT,
                    reviewed_at_utc TEXT
                );

                CREATE TABLE IF NOT EXISTS playbook_progress (
                    task_id TEXT PRIMARY KEY,
                    completed INTEGER NOT NULL,
                    completed_by TEXT,
                    completed_at_utc TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS tenant_memory (
                    memory_id TEXT PRIMARY KEY,
                    track_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS environment_profile (
                    profile_key TEXT PRIMARY KEY,
                    profile_json TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS track_claims (
                    track_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    claimed_at_utc TEXT NOT NULL,
                    notes TEXT
                );
                """
            )

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["event_hash"] if row else "GENESIS_0000000000000000"

    def log_event(
        self,
        *,
        actor: str,
        channel: str,
        action: str,
        target_id: str,
        status: str = "SUCCEEDED",
        rfc_ticket: str = "",
        before_state: Any = None,
        after_state: Any = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            event_uid = f"EVT-{uuid.uuid4().hex[:10].upper()}"
            before_str = json.dumps(before_state, sort_keys=True) if before_state is not None else None
            after_str = json.dumps(after_state, sort_keys=True) if after_state is not None else None

            with self._connect() as conn:
                prev_hash = self._last_hash(conn)
                payload = "|".join(
                    [
                        event_uid,
                        now,
                        actor,
                        channel,
                        action,
                        target_id,
                        rfc_ticket or "",
                        status,
                        before_str or "",
                        after_str or "",
                        rationale or "",
                        prev_hash,
                    ]
                )
                event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_uid, timestamp_utc, actor, channel, action, target_id,
                        rfc_ticket, status, before_json, after_json, rationale,
                        prev_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_uid,
                        now,
                        actor,
                        channel,
                        action,
                        target_id,
                        rfc_ticket,
                        status,
                        before_str,
                        after_str,
                        rationale,
                        prev_hash,
                        event_hash,
                    ),
                )

            record = {
                "event_uid": event_uid,
                "timestamp_utc": now,
                "actor": actor,
                "channel": channel,
                "action": action,
                "target_id": target_id,
                "rfc_ticket": rfc_ticket,
                "status": status,
                "before": before_state,
                "after": after_state,
                "rationale": rationale,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
            }
            with self.jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            return record

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        results = []
        for r in rows:
            results.append(
                {
                    "event_uid": r["event_uid"],
                    "timestamp_utc": r["timestamp_utc"],
                    "actor": r["actor"],
                    "channel": r["channel"],
                    "action": r["action"],
                    "target_id": r["target_id"],
                    "rfc_ticket": r["rfc_ticket"] or "",
                    "status": r["status"],
                    "before": json.loads(r["before_json"]) if r["before_json"] else None,
                    "after": json.loads(r["after_json"]) if r["after_json"] else None,
                    "rationale": r["rationale"] or "",
                    "prev_hash": r["prev_hash"],
                    "event_hash": r["event_hash"],
                }
            )
        return results

    def verify_chain(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        expected_prev = "GENESIS_0000000000000000"
        for idx, r in enumerate(rows):
            if r["prev_hash"] != expected_prev:
                return {"valid": False, "checked": idx + 1, "broken_event": r["event_uid"]}
            payload = "|".join(
                [
                    r["event_uid"],
                    r["timestamp_utc"],
                    r["actor"],
                    r["channel"],
                    r["action"],
                    r["target_id"],
                    r["rfc_ticket"] or "",
                    r["status"],
                    r["before_json"] or "",
                    r["after_json"] or "",
                    r["rationale"] or "",
                    r["prev_hash"],
                ]
            )
            calc = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if calc != r["event_hash"]:
                return {"valid": False, "checked": idx + 1, "broken_event": r["event_uid"]}
            expected_prev = calc
        return {"valid": True, "checked": len(rows), "head_hash": expected_prev}

    def get_rollout_states(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM rollout_state").fetchall()
        return {
            r["control_id"]: {
                "control_id": r["control_id"],
                "current_ring": r["current_ring"],
                "previous_ring": r["previous_ring"],
                "last_rfc": r["last_rfc"],
                "updated_by": r["updated_by"],
                "updated_at_utc": r["updated_at_utc"],
                "history": json.loads(r["history_json"]),
            }
            for r in rows
        }

    def save_rollout_state(
        self,
        *,
        control_id: str,
        new_ring: str,
        previous_ring: str,
        rfc_ticket: str,
        actor: str,
        note: str = "",
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT history_json FROM rollout_state WHERE control_id = ?", (control_id,)
            ).fetchone()
            history = json.loads(existing["history_json"]) if existing else []
            history.append(
                {
                    "timestamp_utc": now,
                    "from_ring": previous_ring,
                    "to_ring": new_ring,
                    "rfc_ticket": rfc_ticket,
                    "actor": actor,
                    "note": note,
                }
            )
            conn.execute(
                """
                INSERT INTO rollout_state (
                    control_id, current_ring, previous_ring, last_rfc,
                    updated_by, updated_at_utc, history_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(control_id) DO UPDATE SET
                    current_ring = excluded.current_ring,
                    previous_ring = excluded.previous_ring,
                    last_rfc = excluded.last_rfc,
                    updated_by = excluded.updated_by,
                    updated_at_utc = excluded.updated_at_utc,
                    history_json = excluded.history_json
                """,
                (control_id, new_ring, previous_ring, rfc_ticket, actor, now, json.dumps(history)),
            )
        return {
            "control_id": control_id,
            "current_ring": new_ring,
            "previous_ring": previous_ring,
            "last_rfc": rfc_ticket,
            "updated_by": actor,
            "updated_at_utc": now,
            "history": history,
        }

    def create_proposal(
        self,
        *,
        actor: str,
        channel: str,
        control_id: str,
        target_ring: str,
        rfc_ticket: str,
        justification: str,
    ) -> dict[str, Any]:
        proposal_id = f"PROP-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO pending_proposals (
                    proposal_id, created_at_utc, actor, channel, control_id,
                    target_ring, rfc_ticket, justification, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL')
                """,
                (proposal_id, now, actor, channel, control_id, target_ring, rfc_ticket, justification),
            )
        self.log_event(
            actor=actor,
            channel=channel,
            action="PROPOSE_CHANGE_ITIL_GATE",
            target_id=control_id,
            rfc_ticket=rfc_ticket,
            status="PENDING_APPROVAL",
            after_state={"proposal_id": proposal_id, "target_ring": target_ring},
            rationale=justification,
        )
        return {
            "proposal_id": proposal_id,
            "created_at_utc": now,
            "actor": actor,
            "channel": channel,
            "control_id": control_id,
            "target_ring": target_ring,
            "rfc_ticket": rfc_ticket,
            "justification": justification,
            "status": "PENDING_APPROVAL",
        }

    def list_proposals(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_proposals ORDER BY created_at_utc DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def resolve_proposal(
        self, proposal_id: str, decision: str, reviewer: str
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if not row:
                return None
            conn.execute(
                """
                UPDATE pending_proposals
                SET status = ?, reviewed_by = ?, reviewed_at_utc = ?
                WHERE proposal_id = ?
                """,
                (decision, reviewer, now, proposal_id),
            )
            updated = dict(row)
            updated["status"] = decision
            updated["reviewed_by"] = reviewer
            updated["reviewed_at_utc"] = now
            return updated

    def get_playbook_progress(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM playbook_progress").fetchall()
        return {
            r["task_id"]: {
                "task_id": r["task_id"],
                "completed": bool(r["completed"]),
                "completed_by": r["completed_by"] or "",
                "completed_at_utc": r["completed_at_utc"] or "",
                "notes": r["notes"] or "",
            }
            for r in rows
        }

    def set_playbook_task(
        self, task_id: str, completed: bool, actor: str = "engineer@local", notes: str = ""
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO playbook_progress (task_id, completed, completed_by, completed_at_utc, notes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    completed = excluded.completed,
                    completed_by = excluded.completed_by,
                    completed_at_utc = excluded.completed_at_utc,
                    notes = excluded.notes
                """,
                (task_id, 1 if completed else 0, actor, now, notes),
            )
        self.log_event(
            actor=actor,
            channel="PLAYBOOK_GUIDE",
            action="PLAYBOOK_TASK_UPDATED",
            target_id=task_id,
            status="SUCCEEDED",
            after_state={"completed": completed},
            rationale=notes or f"Marked playbook task '{task_id}' as {'complete' if completed else 'incomplete'}.",
        )
        return {
            "task_id": task_id,
            "completed": completed,
            "completed_by": actor,
            "completed_at_utc": now,
            "notes": notes,
        }

    def list_memories(self, track_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if track_id:
                rows = conn.execute(
                    "SELECT * FROM tenant_memory WHERE track_id = ? ORDER BY recorded_at_utc DESC",
                    (track_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tenant_memory ORDER BY recorded_at_utc DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def add_memory(
        self,
        *,
        track_id: str,
        category: str,
        summary: str,
        details: str,
        recorded_by: str = "endpoint-architect@local",
    ) -> dict[str, Any]:
        mem_id = f"MEM-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tenant_memory (
                    memory_id, track_id, category, summary, details, recorded_by, recorded_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (mem_id, track_id, category, summary, details, recorded_by, now),
            )
        self.log_event(
            actor=recorded_by,
            channel="TENANT_MEMORY",
            action="RECORD_CONTEXT_MEMORY",
            target_id=track_id,
            status="SUCCEEDED",
            after_state={"memory_id": mem_id, "category": category, "summary": summary},
            rationale=details,
        )
        return {
            "memory_id": mem_id,
            "track_id": track_id,
            "category": category,
            "summary": summary,
            "details": details,
            "recorded_by": recorded_by,
            "recorded_at_utc": now,
        }

    def get_environment_profile(self) -> dict[str, Any]:
        default_profile = {
            "edr_provider": "third_party_disabled",
            "dlp_provider": "third_party_dlp",
            "sccm_state": "mixed_active_and_orphaned",
            "has_avd_kiosks": True,
            "has_win10_stragglers": True,
            "presentation_mode": "classic_ops",
        }
        with self._connect() as conn:
            row = conn.execute(
                "SELECT profile_json FROM environment_profile WHERE profile_key = 'active'"
            ).fetchone()
        if not row:
            return default_profile
        stored = json.loads(row["profile_json"])
        return {**default_profile, **stored}

    def save_environment_profile(
        self, updates: dict[str, Any], actor: str = "endpoint-architect@local"
    ) -> dict[str, Any]:
        current = self.get_environment_profile()
        merged = {**current, **{k: v for k, v in updates.items() if k in current}}
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO environment_profile (profile_key, profile_json, updated_by, updated_at_utc)
                VALUES ('active', ?, ?, ?)
                ON CONFLICT(profile_key) DO UPDATE SET
                    profile_json = excluded.profile_json,
                    updated_by = excluded.updated_by,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (json.dumps(merged), actor, now),
            )
        self.log_event(
            actor=actor,
            channel="ENV_PROFILE",
            action="UPDATE_ENVIRONMENT_STACK",
            target_id="environment-stack-profile",
            status="SUCCEEDED",
            before_state=current,
            after_state=merged,
            rationale="Updated third-party security/co-management coexistence guardrails.",
        )
        return merged

    def list_track_claims(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM track_claims").fetchall()
        return {r["track_id"]: dict(r) for r in rows}

    def claim_track(self, track_id: str, owner: str, notes: str = "") -> dict[str, Any]:
        clean_owner = owner.strip()
        if not clean_owner:
            raise ValueError("owner is required to claim a Track.")
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO track_claims (track_id, owner, claimed_at_utc, notes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(track_id) DO UPDATE SET
                    owner = excluded.owner,
                    claimed_at_utc = excluded.claimed_at_utc,
                    notes = excluded.notes
                """,
                (track_id, clean_owner, now, notes.strip()),
            )
        self.log_event(
            actor=clean_owner,
            channel="TEAM_COORDINATION",
            action="CLAIM_TRACK_OWNER",
            target_id=track_id,
            status="SUCCEEDED",
            after_state={"owner": clean_owner, "notes": notes.strip()},
            rationale=notes.strip() or f"{clean_owner} claimed ownership of track '{track_id}' to prevent overlap.",
        )
        return {"track_id": track_id, "owner": clean_owner, "claimed_at_utc": now, "notes": notes.strip()}

    def release_track(self, track_id: str, actor: str = "endpoint-architect@local") -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            existing = conn.execute("SELECT * FROM track_claims WHERE track_id = ?", (track_id,)).fetchone()
            conn.execute("DELETE FROM track_claims WHERE track_id = ?", (track_id,))
        self.log_event(
            actor=actor,
            channel="TEAM_COORDINATION",
            action="RELEASE_TRACK_OWNER",
            target_id=track_id,
            status="SUCCEEDED",
            before_state=dict(existing) if existing else None,
            rationale=f"Released track ownership lock on '{track_id}'.",
        )
        return {"track_id": track_id, "released": True}
