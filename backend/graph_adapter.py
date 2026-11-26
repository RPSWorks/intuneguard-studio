"""Dual-Mode Tenant Data Adapter (Synthetic Sandbox & Strict-Egress Live Microsoft Graph).

Security Controls for Regulated ARB Review:
1. Strict outbound host allowlist: LiveGraphAdapter refuses any HTTP request not
   targeting login.microsoftonline.com or graph.microsoft.com.
2. Separation of concerns: Read-only tenant discovery works without any write scopes.
3. Zero external packages required: Uses Python 3.12 stdlib urllib.request.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from backend.config import ALLOWED_LIVE_HOSTS, AppConfig
from backend.synthetic_tenant import build_synthetic_tenant


class EgressPolicyViolation(RuntimeError):
    """Raised if code ever attempts to contact a host outside the ARB allowlist."""


class TenantAdapter:
    def fetch_tenant_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError


class SyntheticTenantAdapter(TenantAdapter):
    def __init__(self) -> None:
        self._snapshot = build_synthetic_tenant()

    def fetch_tenant_snapshot(self) -> dict[str, Any]:
        return self._snapshot


class LiveGraphAdapter(TenantAdapter):
    """Read-only Microsoft Graph API adapter with strict domain allowlist enforcement."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._cached_token: str | None = None

    @staticmethod
    def _enforce_allowlist(url: str) -> None:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in ALLOWED_LIVE_HOSTS:
            raise EgressPolicyViolation(
                f"Blocked outbound request to '{host}'. Allowed hosts: {sorted(ALLOWED_LIVE_HOSTS)}"
            )

    def _get_token(self) -> str:
        if self._cached_token:
            return self._cached_token
        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        self._enforce_allowlist(token_url)
        body = urllib.parse.urlencode(
            {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode("utf-8")
        req = urllib.request.Request(token_url, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self._cached_token = data["access_token"]
        return self._cached_token

    def _graph_get_all(self, path: str, max_pages: int = 10) -> list[dict[str, Any]]:
        token = self._get_token()
        url = path if path.startswith("https://") else f"https://graph.microsoft.com{path}"
        items: list[dict[str, Any]] = []
        pages = 0
        while url and pages < max_pages:
            self._enforce_allowlist(url)
            req = urllib.request.Request(
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            items.extend(payload.get("value", []))
            url = payload.get("@odata.nextLink", "")
            pages += 1
        return items

    def fetch_tenant_snapshot(self) -> dict[str, Any]:
        # Real Microsoft Graph endpoints for read-only discovery
        cfg_policies = self._graph_get_all("/beta/deviceManagement/configurationPolicies?$top=100")
        dev_configs = self._graph_get_all("/v1.0/deviceManagement/deviceConfigurations?$top=100")
        compliance = self._graph_get_all("/v1.0/deviceManagement/deviceCompliancePolicies?$top=100")
        groups_raw = self._graph_get_all("/v1.0/groups?$select=id,displayName,groupTypes,membershipRule&$top=100")
        audit_raw = self._graph_get_all("/v1.0/deviceManagement/auditEvents?$top=25")

        policies: list[dict[str, Any]] = []
        for p in cfg_policies:
            policies.append(
                {
                    "id": p.get("id", ""),
                    "name": p.get("name", "Unnamed Settings Catalog"),
                    "category": "Settings Catalog",
                    "setting_key": "live_settings_catalog",
                    "configured_value": p.get("technologies", "mdm"),
                    "assigned_include": [],
                    "assigned_exclude": [],
                    "last_modified": (p.get("lastModifiedDateTime") or "")[:10],
                    "modified_by": "Graph Live",
                    "rfc_tag": None,
                    "status_flag": "healthy",
                    "conflict_reason": "",
                }
            )
        for p in dev_configs:
            policies.append(
                {
                    "id": p.get("id", ""),
                    "name": p.get("displayName", "Unnamed Device Config"),
                    "category": p.get("@odata.type", "Device Configuration").split(".")[-1],
                    "setting_key": "live_device_config",
                    "configured_value": "Live Graph Policy",
                    "assigned_include": [],
                    "assigned_exclude": [],
                    "last_modified": (p.get("lastModifiedDateTime") or "")[:10],
                    "modified_by": "Graph Live",
                    "rfc_tag": None,
                    "status_flag": "healthy",
                    "conflict_reason": "",
                }
            )
        for p in compliance:
            policies.append(
                {
                    "id": p.get("id", ""),
                    "name": p.get("displayName", "Unnamed Compliance Policy"),
                    "category": "Device Compliance",
                    "setting_key": "device_compliance_zero_trust_ca",
                    "configured_value": "Live Compliance Policy",
                    "assigned_include": [],
                    "assigned_exclude": [],
                    "last_modified": (p.get("lastModifiedDateTime") or "")[:10],
                    "modified_by": "Graph Live",
                    "rfc_tag": None,
                    "status_flag": "healthy",
                    "conflict_reason": "",
                }
            )

        groups = [
            {
                "id": g.get("id", ""),
                "name": g.get("displayName", ""),
                "type": "Dynamic" if "DynamicMembership" in (g.get("groupTypes") or []) else "Assigned",
                "rule": g.get("membershipRule"),
                "member_count": 0,
                "nested_children": [],
                "risk_flag": None,
            }
            for g in groups_raw
        ]

        unapproved = [
            {
                "timestamp_utc": e.get("activityDateTime", ""),
                "actor": (e.get("actor") or {}).get("userPrincipalName") or "App/System",
                "policy_name": e.get("displayName", "Intune Change"),
                "change_summary": e.get("activity", ""),
                "rfc_ticket": None,
                "severity": "Medium",
            }
            for e in audit_raw
        ]

        return {
            "tenant": {
                "name": f"Live Microsoft Entra Tenant ({self.config.tenant_id[:8]}...)",
                "tenant_id": self.config.tenant_id,
                "licensing": "Live Tenant (Microsoft Graph API Read-Only)",
                "industry": "Enterprise Production",
                "mode": "live",
                "devices": {"total_managed_windows": 0, "by_segment": {}, "join_state": {}, "os_versions": {}},
            },
            "groups": groups,
            "policies": policies,
            "tattooed_gpos": [],
            "unapproved_changes": unapproved,
            "enterprise_apps": [],
        }


def build_adapter(config: AppConfig) -> TenantAdapter:
    if config.is_live:
        return LiveGraphAdapter(config)
    return SyntheticTenantAdapter()
