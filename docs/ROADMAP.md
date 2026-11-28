# IntuneGuard Studio — Product & Engineering Roadmap

This roadmap tracks shipped milestones and upcoming high-leverage evolutions designed to keep **IntuneGuard Studio** evergreen as Microsoft Intune evolves and teams scale adoption.

---

## Shipped in `v1.0.x` (Baseline Complete)
- **7 Guided Learning Tracks** (`policy-sprawl`, `nested-groups`, `autopilot-esp`, `rbac-maa`, `scope-tags`, `oib-cis-waves`, `device-personas-sccm`) following the `Learn → Inspect → Fix Safely → Save to Tenant Memory` loop.
- **Full Phase 1.5 Live & Offline Snapshot Parity:** Shared normalization across `Export-IntuneGuardSnapshot.ps1` (`POST /api/tenant/import`) and `LiveGraphAdapter` for Settings Catalog/Device Config/Compliance assignments, Autopilot/ESP profiles, custom RBAC roles, Scope Tags, and Windows 10 / Co-Managed device breakdowns.
- **Real On-Prem AD GPO XML Scanner:** XXE-safe `Get-GPOReport -All -ReportType Xml` ingestion for tattooed GPO collision detection.
- **Multi-Engineer Track Ownership & Incident Outage Backtracking:** Soft track claims, symptom-based outage timeline correlation, and 1-click rollback candidates.
- **Enterprise Governance & Optional AI:** Classic Ops default UI, Day-1 SharePoint Agent KB export (`/api/report/sharepoint-kb`), OpenAPI 3.1 contract (`/api/openapi.json`), and Azure APIM AI Gateway-ready MCP endpoint (`POST /mcp` + 9 JSON-RPC 2.0 tools).

---

## `v1.1.0` — Real-World Validation & Deep Graph Parity (Next)
- **Expanded Policy Surface:** Extend `Export-IntuneGuardSnapshot.ps1`, `LiveGraphAdapter`, and snapshot normalization for Endpoint Security `intents`, Platform Scripts, Windows Update Rings, and Feature Update profiles.
- **True Setting-Level Collision Detection:** Parse `configurationPolicies/{id}/settings` (`settingDefinitionId`) to detect exact MDM/OMA-URI collisions instead of relying solely on naming heuristics.
- **Real Nested Group Resolution:** Resolve `/groups/{id}/members` recursively (with cycle detection) for Track 2 real-tenant chains.
- **Intune Assignment Filter Inventory:** Ingest `/beta/deviceManagement/assignmentFilters` for Track 7 kiosk/AVD/persona isolation analysis.

## `v1.2.0` — Offline Drift & Public Interactive Demo
- **Snapshot-vs-Snapshot Diff Engine:** Compare two Path A offline JSON exports locally to surface new/modified/deleted policies, assignment drift, and unapproved portal edits without requiring persistent live Graph credentials.
- **Static GitHub Pages Interactive Demo:** Optional read-only static build (`https://rpsworks.github.io/intuneguard-studio/`) for zero-backend portfolio and peer demos.

## `v2.0.0` — Evergreen Catalog & Enterprise IaC
- **Externalized OIB / CIS Baseline Packs:** Move OpenIntuneBaseline and CIS Intune Benchmark definitions into versioned JSON packs with automated *"New Control Available"* / *"Setting Deprecated"* diffing.
- **Enterprise Azure IaC:** Reference Bicep template for Azure Container Apps + Azure APIM AI Gateway + Managed Identity deployment.
- **Automated Drift Webhooks:** Scheduled read-only Graph polling pushing human-readable before/after diffs to Microsoft Teams, ServiceNow, or Jira.
