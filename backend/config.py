"""Runtime configuration & strict security boundaries for IntuneGuard Studio.

Designed for regulated financial/enterprise Architecture Review Boards (ARB):
- Defaults to zero-egress 'synthetic' mode for safe demos, testing, and CAB walkthroughs.
- Enforces an explicit outbound domain allowlist when 'live' Microsoft Graph mode is enabled.
- Supports certificate/Managed Identity/Workload Identity Federation patterns (never hardcodes secrets).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("INTUNEGUARD_DATA_DIR", str(PROJECT_ROOT / "data")))
WEB_DIR = PROJECT_ROOT / "web"

ALLOWED_LIVE_HOSTS = frozenset({
    "login.microsoftonline.com",
    "graph.microsoft.com",
})


@dataclass(frozen=True)
class AppConfig:
    mode: str = field(default_factory=lambda: os.environ.get("INTUNEGUARD_MODE", "synthetic").lower())
    host: str = field(default_factory=lambda: os.environ.get("INTUNEGUARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("INTUNEGUARD_PORT", "8095")))
    tenant_id: str = field(default_factory=lambda: os.environ.get("AZURE_TENANT_ID", ""))
    client_id: str = field(default_factory=lambda: os.environ.get("AZURE_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.environ.get("AZURE_CLIENT_SECRET", ""))
    allow_live_writes: bool = field(
        default_factory=lambda: os.environ.get("INTUNEGUARD_ALLOW_WRITES", "false").lower() == "true"
    )
    require_rfc_for_writes: bool = field(
        default_factory=lambda: os.environ.get("INTUNEGUARD_REQUIRE_RFC", "true").lower() == "true"
    )
    apim_gateway_key: str = field(default_factory=lambda: os.environ.get("INTUNEGUARD_APIM_KEY", ""))
    json_logs: bool = field(
        default_factory=lambda: os.environ.get("INTUNEGUARD_JSON_LOGS", "false").lower() == "true"
    )
    db_path: Path = field(default_factory=lambda: DATA_DIR / "intuneguard_audit.db")
    jsonl_log_path: Path = field(default_factory=lambda: DATA_DIR / "itil_audit_trail.jsonl")

    @property
    def is_live(self) -> bool:
        return self.mode == "live" and bool(self.tenant_id and self.client_id)


def load_config() -> AppConfig:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return AppConfig()
