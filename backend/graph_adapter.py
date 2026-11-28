"""Dual-Mode Tenant Data Adapter (Synthetic Sandbox & Strict-Egress Live Microsoft Graph).

Security Controls for Regulated ARB Review:
1. Strict outbound host allowlist: LiveGraphAdapter refuses any HTTP request not
   targeting login.microsoftonline.com or graph.microsoft.com.
2. Separation of concerns: Read-only tenant discovery works without any write scopes.
3. Zero external packages required: Uses Python 3.12 stdlib urllib.request.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from backend.config import ALLOWED_LIVE_HOSTS, AppConfig
from backend.snapshot_normalizer import normalize_graph_payload
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

    def _graph_get_safe(self, path: str, max_pages: int = 10) -> list[dict[str, Any]]:
        """Best-effort Graph pull for optional scopes (never suppresses EgressPolicyViolation)."""
        try:
            return self._graph_get_all(path, max_pages=max_pages)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            return []

    def fetch_tenant_snapshot(self) -> dict[str, Any]:
        # Real Microsoft Graph endpoints matching Export-IntuneGuardSnapshot.ps1 (Phase 1.5 parity)
        org_items = self._graph_get_safe("/v1.0/organization?$select=id,displayName", max_pages=1)
        org = org_items[0] if org_items else {}

        cfg_policies = self._graph_get_all("/beta/deviceManagement/configurationPolicies?$expand=assignments&$top=100")
        dev_configs = self._graph_get_all("/v1.0/deviceManagement/deviceConfigurations?$expand=assignments&$top=100")
        compliance = self._graph_get_all("/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments&$top=100")
        groups_raw = self._graph_get_all("/v1.0/groups?$select=id,displayName,groupTypes,membershipRule&$top=100")

        autopilot_raw = self._graph_get_safe("/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$top=100")
        enrollment_cfgs = self._graph_get_safe("/beta/deviceManagement/deviceEnrollmentConfigurations?$top=100")
        esp_raw = [
            e for e in enrollment_cfgs
            if "EnrollmentCompletionPage" in str(e.get("@odata.type") or "")
        ]
        roles_raw = [
            r for r in self._graph_get_safe("/v1.0/deviceManagement/roleDefinitions?$top=100")
            if not r.get("isBuiltIn")
        ]
        scope_tags_raw = self._graph_get_safe("/beta/deviceManagement/roleScopeTags?$top=100")
        devices_raw = self._graph_get_safe(
            "/v1.0/deviceManagement/managedDevices?"
            "$filter=operatingSystem%20eq%20'Windows'&"
            "$select=id,deviceName,osVersion,complianceState,joinType,managementAgent&$top=100"
        )
        audit_raw = self._graph_get_safe("/v1.0/deviceManagement/auditEvents?$top=50", max_pages=1)

        win10_count = sum(
            1 for d in devices_raw if str(d.get("osVersion") or "").startswith("10.0.19")
        )
        co_managed_count = sum(
            1 for d in devices_raw if "configurationmanager" in str(d.get("managementAgent") or "").lower()
        )

        join_counts: dict[str, int] = {}
        os_counts: dict[str, int] = {}
        for d in devices_raw:
            jt = str(d.get("joinType") or "Unknown")
            join_counts[jt] = join_counts.get(jt, 0) + 1
            osv = str(d.get("osVersion") or "")
            os_label = "Windows 10 (EOL)" if osv.startswith("10.0.19") else ("Windows 11" if osv.startswith("10.0.2") else "Windows Other")
            os_counts[os_label] = os_counts.get(os_label, 0) + 1

        raw_payload = {
            "tenant_name": org.get("displayName") or f"Live Microsoft Entra Tenant ({self.config.tenant_id[:8]}...)",
            "tenant_id": org.get("id") or self.config.tenant_id,
            "configuration_policies": cfg_policies,
            "device_configurations": dev_configs,
            "compliance_policies": compliance,
            "groups": groups_raw,
            "autopilot_profiles": autopilot_raw,
            "esp_profiles": esp_raw,
            "custom_roles": roles_raw,
            "scope_tags": scope_tags_raw,
            "windows_devices_count": len(devices_raw),
            "windows_10_count": win10_count,
            "co_managed_count": co_managed_count,
            "devices_join_state": join_counts,
            "devices_os_versions": os_counts,
            "audit_events": audit_raw,
        }
        return normalize_graph_payload(
            raw_payload,
            mode="live",
            licensing="Live Tenant (Microsoft Graph API Read-Only)",
            industry="Enterprise Production",
            modified_by="Graph Live",
            require_policies=False,
        )


def build_adapter(config: AppConfig) -> TenantAdapter:
    if config.is_live:
        return LiveGraphAdapter(config)
    return SyntheticTenantAdapter()
