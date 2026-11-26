const state = {
  tracksData: null,
  activeTrackId: null,
  activeTrackStep: 1,
  envProfile: null,
  playbook: null,
  overview: null,
  controls: [],
  audit: null,
  memories: [],
  mcpTools: [],
  policyPage: 1,
};

function esc(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function toast(msg, isError = false) {
  const area = document.getElementById("toast-area");
  const el = document.createElement("div");
  el.className = `toast${isError ? " error" : ""}`;
  el.textContent = msg;
  area.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

async function apiGet(url) {
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiPost(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function initTheme() {
  const saved = localStorage.getItem("intuneguard_theme");
  const preferred = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  applyTheme(preferred);
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("intuneguard_theme", theme);
  const btn = document.getElementById("theme-toggle-btn");
  if (btn) btn.textContent = theme === "dark" ? "☀️ Light Mode" : "🌙 Dark Mode";
}

function applyPresentationMode() {
  const isAi = state.envProfile?.presentation_mode === "ai_mcp";
  const btn = document.getElementById("pres-mode-btn");
  const navLbl = document.getElementById("nav-memory-label");
  const mcpPanel = document.getElementById("mcp-panel");

  btn.textContent = isAi ? "AI / MCP View: ON" : "Classic Ops View";
  btn.classList.toggle("btn-primary", isAi);
  btn.classList.toggle("btn-secondary", !isAi);
  navLbl.textContent = isAi ? "3. Tenant Memory & MCP" : "3. Tenant Memory & CAB";
  mcpPanel.style.display = isAi ? "block" : "none";
}

function switchTab(tabId) {
  const isAi = state.envProfile?.presentation_mode === "ai_mcp";
  const titles = {
    tracks: "Pick ONE Intune Pitfall to Solve Today",
    connect: "Connect Your Tenant & Stack Coexistence Profile",
    memory: isAi ? "Growing Tenant Memory, CAB Queue & MCP Server" : "Growing Tenant Memory & Change Approval Queue",
    explorer: "Deep Policy Explorer, Self-Healing Scripts & Audit Log",
  };
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.tab === tabId));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${tabId}`));
  document.getElementById("page-title").textContent = titles[tabId] || "IntuneGuard Studio";
}

function sevBadge(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return `<span class="badge badge-danger">${esc(sev)}</span>`;
  if (s === "medium") return `<span class="badge badge-warn">${esc(sev)}</span>`;
  return `<span class="badge badge-success">${esc(sev || "Low")}</span>`;
}

function statusBadge(status) {
  const s = (status || "").toLowerCase();
  if (s.includes("conflict") || s.includes("unapproved")) return `<span class="badge badge-danger">${esc(status)}</span>`;
  if (s.includes("duplicate") || s.includes("orphaned") || s.includes("skip") || s.includes("coexistence")) {
    return `<span class="badge badge-warn">${esc(status)}</span>`;
  }
  if (s.includes("healthy") || s.includes("deployed")) return `<span class="badge badge-success">${esc(status)}</span>`;
  return `<span class="badge badge-info">${esc(status)}</span>`;
}

async function refreshAll() {
  try {
    const [tracksData, playbook, overview, baseline, audit, memoryResp, mcpTools, envProfile] = await Promise.all([
      apiGet("/api/tracks"),
      apiGet("/api/playbook"),
      apiGet("/api/overview"),
      apiGet("/api/baseline"),
      apiGet("/api/audit"),
      apiGet("/api/memory"),
      apiGet("/api/mcp/tools"),
      apiGet("/api/environment"),
    ]);
    state.tracksData = tracksData;
    state.playbook = playbook;
    state.overview = overview;
    state.controls = baseline.controls;
    state.audit = audit;
    state.memories = memoryResp.memories;
    state.mcpTools = mcpTools.tools;
    state.envProfile = envProfile;

    applyPresentationMode();
    renderHeader();
    renderTracksView();
    renderConnectView();
    renderMemoryAndMcp();
    renderExplorerHelpers();
    await Promise.all([loadPolicies(state.policyPage), runBacktrack()]);
  } catch (err) {
    toast(`Failed to load studio data: ${err.message}`, true);
  }
}

function renderHeader() {
  const t = state.overview.tenant;
  document.getElementById("tenant-subtitle").textContent =
    `${t.name} • ${t.devices.total_managed_windows || 0} Windows Devices • ${state.overview.kpis.total_policies} Policies`;

  const modeBadge = document.getElementById("mode-badge");
  const resetBtn = document.getElementById("reset-sandbox-btn");
  if (t.mode === "live") {
    modeBadge.textContent = "LIVE GRAPH (ALLOWLISTED)";
    modeBadge.className = "badge badge-warn";
    resetBtn.style.display = "none";
  } else if (t.mode === "imported") {
    modeBadge.textContent = "IMPORTED REAL SNAPSHOT";
    modeBadge.className = "badge badge-success";
    resetBtn.style.display = "inline-flex";
  } else {
    modeBadge.textContent = "SYNTHETIC SANDBOX";
    modeBadge.className = "badge badge-info";
    resetBtn.style.display = "none";
  }

  const chain = state.overview.audit_chain_integrity;
  const chainBadge = document.getElementById("chain-badge");
  chainBadge.textContent = chain.valid ? `HASH CHAIN OK (${chain.checked})` : "HASH CHAIN BROKEN";
  chainBadge.className = `badge ${chain.valid ? "badge-success" : "badge-danger"}`;
}

function renderTracksView() {
  const td = state.tracksData;
  document.getElementById("mastery-pct").textContent = `${td.mastery_pct}%`;
  document.getElementById("mastery-sub").textContent =
    `${td.completed_tracks} / ${td.total_tracks} tracks mastered • ${td.memory_entries_count} context memories`;
  document.getElementById("mastery-bar").style.width = `${td.mastery_pct}%`;

  const ep = state.envProfile || {};
  const alerts = [];
  if (ep.edr_provider === "third_party_disabled") alerts.push("3rd-Party EDR Active (Defender Disabled — ASR/RTP Lockout Guardrail ON)");
  if (ep.dlp_provider === "third_party_dlp") alerts.push("3rd-Party DLP Active");
  if (ep.sccm_state === "mixed_active_and_orphaned") alerts.push("Active + Orphaned ConfigMgr Present");
  const banner = document.getElementById("coex-banner");
  if (alerts.length) {
    banner.style.display = "flex";
    banner.innerHTML = `
      <div><strong>Active Coexistence Guardrails:</strong> ${esc(alerts.join(" • "))}</div>
      <button class="btn btn-secondary btn-small" data-jump-tab="connect">Edit Stack Profile</button>`;
  } else {
    banner.style.display = "none";
  }

  const launcher = document.getElementById("tracks-launcher");
  const workspace = document.getElementById("track-workspace");

  if (!state.activeTrackId) {
    launcher.style.display = "block";
    workspace.style.display = "none";
    document.getElementById("tracks-grid").innerHTML = td.tracks
      .map(
        (tr) => `
        <article class="track-card ${tr.completed ? "done" : ""}" data-open-track="${esc(tr.id)}">
          <div class="control-top">
            <span class="badge badge-info">Track ${tr.order}</span>
            <span class="badge ${tr.completed ? "badge-success" : "badge-warn"}">
              ${tr.completed ? "Mastered ✓" : `${tr.findings_count} Findings`}
            </span>
          </div>
          <h3>${esc(tr.title)}</h3>
          <p>${esc(tr.tagline)}</p>
          <div class="control-meta">
            <span class="badge badge-neutral">${esc(tr.difficulty)}</span>
            <span class="badge badge-neutral">${esc(tr.time_estimate)}</span>
            ${
              tr.owner
                ? `<span class="badge badge-info">Owner: ${esc(tr.owner)}</span>`
                : `<span class="badge badge-neutral">Unclaimed</span>`
            }
          </div>
          <div class="track-footer">
            <span>${tr.memory_count} saved ${tr.memory_count === 1 ? "memory" : "memories"}</span>
            <strong style="color:var(--accent);">Start Guided Track →</strong>
          </div>
        </article>`
      )
      .join("");
    return;
  }

  const tr = td.tracks.find((x) => x.id === state.activeTrackId);
  if (!tr) {
    state.activeTrackId = null;
    renderTracksView();
    return;
  }
  launcher.style.display = "none";
  workspace.style.display = "block";

  const step = state.activeTrackStep;
  let bodyHtml = "";

  if (step === 1) {
    bodyHtml = `
      <div class="learn-grid">
        <div class="learn-box">
          <h3>What Is This Pitfall?</h3>
          <p>${esc(tr.learn.what_it_is)}</p>
        </div>
        <div class="learn-box">
          <h3>Why It Silently Breaks Tenants</h3>
          <p>${esc(tr.learn.why_it_breaks)}</p>
        </div>
        <div class="learn-box" style="border-color:rgba(22,163,74,0.5);">
          <h3 style="color:var(--success);">Senior Architect Rule</h3>
          <p>${esc(tr.learn.architect_rule)}</p>
        </div>
      </div>`;
  } else if (step === 2) {
    bodyHtml = `
      <p class="muted-note">Showing <strong>only</strong> findings relevant to <strong>${esc(tr.title)}</strong>:</p>
      <div class="stack-list">
        ${tr.inspect_items
          .map((item) => {
            const ctrlMatch = item.control_id ? state.controls.find((c) => c.id === item.control_id) : null;
            return `
            <div class="list-card">
              <div class="list-card-top">
                <div class="list-card-title">${esc(item.title)}</div>
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                  ${ctrlMatch ? statusBadge(ctrlMatch.diff_status) : ""}
                  ${item.current_ring ? `<span class="badge badge-info">${esc(item.current_ring)}</span>` : ""}
                  ${sevBadge(item.severity)}
                </div>
              </div>
              <div class="muted-note" style="margin-bottom:6px;">${esc(item.detail)}</div>
              ${
                item.examples?.length
                  ? `<ul style="margin:0 0 8px;padding-left:18px;font-size:12px;">
                      ${item.examples.map((ex) => `<li>${esc(ex)}</li>`).join("")}
                    </ul>`
                  : ""
              }
              ${
                item.control_id
                  ? `<div class="btn-row">
                      <button class="btn btn-secondary btn-small" data-inspect="${esc(item.control_id)}">Dry-Run Diff &amp; Rationale</button>
                      ${item.can_promote ? `<button class="btn btn-primary btn-small" data-ring-action="promote" data-cid="${esc(item.control_id)}">Stage Next Ring</button>` : ""}
                      ${item.can_rollback ? `<button class="btn btn-danger btn-small" data-ring-action="rollback" data-cid="${esc(item.control_id)}">Rollback</button>` : ""}
                    </div>`
                  : ""
              }
            </div>`;
          })
          .join("")}
      </div>`;
  } else if (step === 3) {
    bodyHtml = `
      <div class="path-card" style="margin-bottom:14px;">
        <div class="list-card-title">Safe Remediation Sequence (Zero-Surprise Order)</div>
        <ol class="step-ol">
          ${tr.fix.steps.map((s) => `<li>${esc(s)}</li>`).join("")}
        </ol>
        <div class="btn-row">
          ${
            tr.fix.script_download_url
              ? `<a class="btn btn-primary btn-small" href="${esc(tr.fix.script_download_url)}" download>Download ${esc(tr.fix.script_name)}</a>
                 <button class="btn btn-secondary btn-small" id="copy-track-script">Copy PowerShell Script</button>`
              : `<button class="btn btn-primary btn-small" data-track-step="2">Back to Controls to Promote Waves →</button>`
          }
          <button class="btn btn-secondary btn-small" data-jump-tab="${esc(tr.fix.deep_link_tab)}">Open Related View →</button>
        </div>
      </div>
      ${
        tr.fix.script_content
          ? `<details class="script-drawer" open>
              <summary>Inspect ${esc(tr.fix.script_name)} (Read-Only / Dry-Run Safe)</summary>
              <pre id="active-track-script" class="code-block">${esc(tr.fix.script_content)}</pre>
            </details>`
          : ""
      }`;
  } else if (step === 4) {
    const existingMems = state.memories.filter((m) => m.track_id === tr.id);
    bodyHtml = `
      <div class="two-col" style="margin-bottom:0;">
        <form id="track-memory-form" class="path-card">
          <div class="list-card-title">Save What You Cleaned or Decided to Tenant Memory</div>
          <p class="muted-note" style="margin:0;">
            Builds permanent historical context so your team can backtrack outages, satisfy auditors, and avoid undoing each other's cleanup.
          </p>
          <input type="hidden" id="mem-track-id" value="${esc(tr.id)}">
          <input type="hidden" id="mem-category" value="${esc(tr.memory_template.category)}">
          <div class="field" style="margin-bottom:4px;">
            <label for="mem-summary">One-Line Standard or Cleanup Summary</label>
            <input id="mem-summary" type="text" required value="${esc(tr.memory_template.default_summary)}">
          </div>
          <div class="field" style="margin-bottom:4px;">
            <label for="mem-details">Context, Exceptions &amp; Rationale</label>
            <textarea id="mem-details" rows="4">${esc(tr.memory_template.default_details)}</textarea>
          </div>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--text);">
            <input id="mem-mark-done" type="checkbox" checked style="width:auto;">
            <span>Mark Track ${tr.order} (${esc(tr.title)}) as Mastered</span>
          </label>
          <div class="btn-row">
            <button type="submit" class="btn btn-primary">Save to Tenant Memory &amp; Audit Chain</button>
          </div>
        </form>

        <div class="path-card">
          <div class="list-card-title">Saved Context for This Track (${existingMems.length})</div>
          ${
            existingMems.length
              ? existingMems
                  .map(
                    (m) => `
                    <div class="list-card">
                      <div class="list-card-title">${esc(m.summary)}</div>
                      <div class="muted-note" style="margin:4px 0;">${esc(m.details)}</div>
                      <div style="font-size:11px;color:var(--muted);"><code>${esc(m.memory_id)}</code> • ${esc(m.recorded_at_utc.slice(0, 16).replace("T", " "))} UTC</div>
                    </div>`
                  )
                  .join("")
              : `<p class="muted-note">No memory saved for this track yet. Submit the form on the left to record your tenant's baseline standard.</p>`
          }
        </div>
      </div>`;
  }

  workspace.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div>
          <button class="btn btn-secondary btn-small" id="back-to-tracks" style="margin-bottom:8px;">← Back to All ${td.total_tracks} Tracks</button>
          <h2 style="font-size:18px;">Track ${tr.order}: ${esc(tr.title)}</h2>
        </div>
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
          ${
            tr.owner
              ? `<span class="badge badge-info">Owner: ${esc(tr.owner)}</span>
                 <button class="btn btn-secondary btn-small" data-release-track="${esc(tr.id)}">Release Claim</button>`
              : `<button class="btn btn-secondary btn-small" data-claim-track="${esc(tr.id)}">Claim Track (Prevent Overlap)</button>`
          }
          <span class="badge badge-neutral">${esc(tr.time_estimate)}</span>
          <span class="badge ${tr.completed ? "badge-success" : "badge-info"}">${tr.completed ? "Mastered ✓" : "In Progress"}</span>
        </div>
      </div>

      <div class="step-bar" role="tablist">
        <button class="step-pill ${step === 1 ? "active" : ""}" data-track-step="1">1. Learn (30 sec)</button>
        <button class="step-pill ${step === 2 ? "active" : ""}" data-track-step="2">2. Inspect (${tr.inspect_items.length})</button>
        <button class="step-pill ${step === 3 ? "active" : ""}" data-track-step="3">3. Fix Safely</button>
        <button class="step-pill ${step === 4 ? "active" : ""}" data-track-step="4">4. Save to Memory</button>
      </div>

      ${bodyHtml}

      <div class="pager" style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border);">
        ${step > 1 ? `<button class="btn btn-secondary" data-track-step="${step - 1}">← Previous Step</button>` : `<span></span>`}
        ${step < 4 ? `<button class="btn btn-primary" data-track-step="${step + 1}">Next Step →</button>` : `<button class="btn btn-secondary" id="back-to-tracks-bottom">Done — Pick Next Track →</button>`}
      </div>
    </div>`;
}

function renderConnectView() {
  if (state.envProfile) {
    document.getElementById("env-edr").value = state.envProfile.edr_provider;
    document.getElementById("env-dlp").value = state.envProfile.dlp_provider;
    document.getElementById("env-sccm").value = state.envProfile.sccm_state;
  }

  const scripts = state.playbook.scripts;
  document.getElementById("connect-cards").innerHTML = `
    <div class="path-card recommended">
      <div class="list-card-top">
        <div class="list-card-title">Path A: Offline Read-Only Snapshot (Start Today — Zero ARB Wait)</div>
        <span class="badge badge-info">RECOMMENDED FIRST</span>
      </div>
      <p class="muted-note" style="margin:0;">
        Exports real Policies, Groups, Autopilot/ESP, Custom RBAC Roles, Scope Tags, Win10/Co-Mgmt counts, and Audit Logs using your existing read-only Graph sign-in.
      </p>
      <ol class="step-ol">
        <li>Download and run <code>Export-IntuneGuardSnapshot.ps1</code> from PowerShell.</li>
        <li>Upload <code>intuneguard_snapshot.json</code> below to populate all 7 Learning Tracks with real tenant data.</li>
      </ol>
      <div class="btn-row">
        <a class="btn btn-primary btn-small" href="/api/scripts/export_snapshot" download>Download Export-IntuneGuardSnapshot.ps1</a>
        <button class="btn btn-secondary btn-small" data-copy-raw="export_snapshot">Copy Script</button>
      </div>
      <div class="upload-zone">
        <label for="snapshot-file-input"><strong>Upload Real Intune Snapshot (.json)</strong></label>
        <input id="snapshot-file-input" type="file" accept=".json,application/json">
        <button id="snapshot-upload-btn" class="btn btn-primary btn-small" style="align-self:flex-start;">Import Intune Snapshot</button>
      </div>
      <div class="upload-zone">
        <label for="gpo-file-input"><strong>Optional: Upload On-Prem AD GPO Report (.xml)</strong></label>
        <div class="muted-note" style="margin:0;">Export via: <code>Get-GPOReport -All -ReportType Xml -Path .\\ad_gpos.xml</code></div>
        <input id="gpo-file-input" type="file" accept=".xml,text/xml,application/xml">
        <button id="gpo-upload-btn" class="btn btn-secondary btn-small" style="align-self:flex-start;">Scan GPO XML for Intune Collisions</button>
      </div>
      <details class="script-drawer">
        <summary>Inspect Export-IntuneGuardSnapshot.ps1 (Phase 1.5 Full Parity)</summary>
        <pre class="code-block">${esc(scripts.export_snapshot.content)}</pre>
      </details>
    </div>

    <div class="path-card">
      <div class="list-card-top">
        <div class="list-card-title">Path B: Live Read-Only App Registration (Post-ARB Ongoing)</div>
        <span class="badge badge-neutral">CONTINUOUS LIVE</span>
      </div>
      <p class="muted-note" style="margin:0;">
        For ongoing live Graph sync after Architecture Review Board approval. Uses an X.509 certificate (zero client secrets) and strictly <code>*.Read.All</code> scopes.
      </p>
      <ol class="step-ol">
        <li>Submit <code>docs/SECURITY_ARB_PACKAGE.md</code> and <code>docs/GRAPH_PERMISSIONS_MATRIX.md</code> to InfoSec.</li>
        <li>Run <code>New-IntuneGuardAppReg.ps1</code> and click Grant Admin Consent in Entra.</li>
        <li>Double-click <code>Start-IntuneGuard.bat</code> (Windows) or run Docker with <code>INTUNEGUARD_MODE=live</code>.</li>
      </ol>
      <div class="btn-row">
        <a class="btn btn-secondary btn-small" href="/api/scripts/app_registration" download>Download New-IntuneGuardAppReg.ps1</a>
        <button class="btn btn-secondary btn-small" data-copy-raw="app_registration">Copy Script</button>
      </div>
      <details class="script-drawer">
        <summary>Inspect New-IntuneGuardAppReg.ps1</summary>
        <pre class="code-block">${esc(scripts.app_registration.content)}</pre>
      </details>
    </div>`;

  document.getElementById("e7-list").innerHTML = state.overview.e7_compatibility.included_capabilities_used
    .map((item) => `<li>${esc(item)}</li>`)
    .join("");
}

function renderMemoryAndMcp() {
  document.getElementById("memory-count-badge").textContent = `${state.memories.length} Saved`;
  document.getElementById("memory-list").innerHTML = state.memories.length
    ? state.memories
        .map(
          (m) => `
          <div class="list-card">
            <div class="list-card-top">
              <div class="list-card-title">${esc(m.summary)}</div>
              <span class="badge badge-info">${esc(m.track_id)}</span>
            </div>
            <div class="muted-note" style="margin-bottom:4px;">${esc(m.details)}</div>
            <div style="font-size:11px;color:var(--muted);">
              <code>${esc(m.memory_id)}</code> • ${esc(m.category)} • ${esc(m.recorded_by)} • ${esc(m.recorded_at_utc.slice(0, 16).replace("T", " "))} UTC
            </div>
          </div>`
        )
        .join("")
    : `<p class="muted-note">No tenant memories saved yet. Complete Step 4 inside any Learning Track to build permanent team context and outage history.</p>`;

  const sel = document.getElementById("mcp-tool-select");
  const prev = sel.value;
  sel.innerHTML = state.mcpTools.map((t) => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join("");
  sel.value = prev || "get_tenant_context_memory";
  if (!document.getElementById("mcp-args-input").value) {
    document.getElementById("mcp-args-input").value = "{}";
  }

  const pending = state.audit.proposals.filter((p) => p.status === "PENDING_APPROVAL");
  document.getElementById("proposal-count-badge").textContent = `${pending.length} Pending`;
  document.getElementById("proposals-list").innerHTML = state.audit.proposals.length
    ? state.audit.proposals
        .map(
          (p) => `
          <div class="list-card">
            <div class="list-card-top">
              <div class="list-card-title"><code>${esc(p.proposal_id)}</code> • ${esc(p.control_id)} → ${esc(p.target_ring)}</div>
              <span class="badge ${p.status === "PENDING_APPROVAL" ? "badge-warn" : p.status === "APPROVED" ? "badge-success" : "badge-danger"}">${esc(p.status)}</span>
            </div>
            <div class="muted-note" style="margin-bottom:6px;">
              RFC: <code>${esc(p.rfc_ticket)}</code> • Actor: <code>${esc(p.actor)}</code><br>${esc(p.justification)}
            </div>
            ${
              p.status === "PENDING_APPROVAL"
                ? `<div class="btn-row">
                    <button class="btn btn-primary btn-small" data-prop-decision="APPROVED" data-pid="${esc(p.proposal_id)}">Approve &amp; Execute</button>
                    <button class="btn btn-danger btn-small" data-prop-decision="REJECTED" data-pid="${esc(p.proposal_id)}">Reject</button>
                  </div>`
                : `<div style="font-size:11.5px;color:var(--muted);">Reviewed by ${esc(p.reviewed_by || "CAB")}</div>`
            }
          </div>`
        )
        .join("")
    : `<p class="muted-note">No write proposals queued yet. Switch to AI / MCP View in the top bar to test automated RFC proposals, or promote controls directly inside Track 6.</p>`;
}

function renderExplorerHelpers() {
  const sel = document.getElementById("script-control-select");
  const prevVal = sel.value;
  sel.innerHTML = state.controls.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${esc(c.self_healing.name)}</option>`).join("");
  if (prevVal) sel.value = prevVal;
  renderSelectedScript();

  const chain = state.audit.chain_integrity;
  const badge = document.getElementById("audit-integrity-label");
  badge.textContent = chain.valid ? `VERIFIED (${chain.checked} EVENTS)` : `BROKEN AT ${chain.broken_event}`;
  badge.className = `badge ${chain.valid ? "badge-success" : "badge-danger"}`;

  document.getElementById("audit-table-body").innerHTML = state.audit.events
    .map(
      (e) => `
      <tr>
        <td>${esc(e.timestamp_utc.slice(0, 19).replace("T", " "))}</td>
        <td><code>${esc(e.event_uid)}</code></td>
        <td>${esc(e.actor)}<br><small style="color:var(--muted);">${esc(e.channel)}</small></td>
        <td><strong>${esc(e.action)}</strong></td>
        <td><code>${esc(e.target_id)}</code></td>
        <td>${e.rfc_ticket ? `<code>${esc(e.rfc_ticket)}</code>` : "—"}</td>
        <td><code>${esc(e.event_hash.slice(0, 16))}…</code></td>
      </tr>`
    )
    .join("");
}

function renderSelectedScript() {
  const id = document.getElementById("script-control-select").value;
  const c = state.controls.find((x) => x.id === id) || state.controls[0];
  if (!c) return;
  document.getElementById("script-meta").innerHTML =
    `Package: <code>${esc(c.self_healing.name)}</code> • Licensed via: <em>${esc(c.e7_component)}</em>`;
  document.getElementById("detect-code").textContent = c.self_healing.detect_ps1;
  document.getElementById("remediate-code").textContent = c.self_healing.remediate_ps1;
}

async function runBacktrack() {
  const q = encodeURIComponent(document.getElementById("backtrack-query")?.value.trim() || "");
  const data = await apiGet(`/api/backtrack?q=${q}`);
  const box = document.getElementById("backtrack-results");
  if (!box) return;

  const rollHtml = data.rollback_candidates.length
    ? `<div class="panel" style="background:var(--card-bg);margin-bottom:14px;">
        <div class="panel-header"><h2 style="font-size:14px;">1-Click Rollback Candidates (${data.rollback_candidates.length})</h2></div>
        <div class="stack-list">
          ${data.rollback_candidates
            .map(
              (r) => `
              <div class="list-card">
                <div class="list-card-top">
                  <div class="list-card-title"><code>${esc(r.control_id)}</code> • ${esc(r.name)}</div>
                  <button class="btn btn-danger btn-small" data-ring-action="rollback" data-cid="${esc(r.control_id)}">Rollback From ${esc(r.current_ring)}</button>
                </div>
                <div class="muted-note" style="margin:0;">${esc(r.what_breaks_in_prod)}</div>
              </div>`
            )
            .join("")}
        </div>
      </div>`
    : "";

  const memHtml = data.related_memories.length
    ? `<div style="margin-bottom:14px;">
        <h3 style="margin:0 0 8px;font-size:13px;color:var(--accent);">Related Tenant Context Memories (${data.related_memories.length})</h3>
        <div class="stack-list">
          ${data.related_memories
            .map((m) => `<div class="list-card"><div class="list-card-title">${esc(m.summary)}</div><div class="muted-note" style="margin:2px 0 0;">${esc(m.details)}</div></div>`)
            .join("")}
        </div>
      </div>`
    : "";

  const tlHtml = data.timeline.length
    ? `<div class="stack-list">
        ${data.timeline
          .map(
            (ev) => `
            <div class="list-card">
              <div class="list-card-top">
                <div class="list-card-title">${esc(ev.title)}</div>
                <div style="display:flex;gap:6px;">
                  <span class="badge ${ev.source === "UNAPPROVED_PORTAL_EDIT" ? "badge-danger" : "badge-info"}">${esc(ev.source)}</span>
                  <span class="badge badge-neutral">RFC: ${esc(ev.rfc_ticket)}</span>
                </div>
              </div>
              <div class="muted-note" style="margin-bottom:4px;">${esc(ev.detail)}</div>
              <div style="font-size:11px;color:var(--muted);">${esc((ev.timestamp_utc || "").slice(0, 19).replace("T", " "))} UTC • Actor: <code>${esc(ev.actor)}</code></div>
            </div>`
          )
          .join("")}
      </div>`
    : `<p class="muted-note">No matching change events found for that symptom.</p>`;

  box.innerHTML = rollHtml + memHtml + `<h3 style="margin:0 0 8px;font-size:13px;">Correlated Change Timeline (${data.timeline_count})</h3>` + tlHtml;
}

async function loadPolicies(page = 1) {
  state.policyPage = page;
  const q = encodeURIComponent(document.getElementById("pol-search").value.trim());
  const status = encodeURIComponent(document.getElementById("pol-status").value);
  const data = await apiGet(`/api/policies?q=${q}&status=${status}&page=${page}&page_size=20`);

  document.getElementById("policy-count-label").textContent = `${data.total} Matching Policies`;
  document.getElementById("pol-page-info").textContent = `Page ${data.page} of ${data.total_pages} (${data.total} policies)`;
  document.getElementById("pol-prev").disabled = data.page <= 1;
  document.getElementById("pol-next").disabled = data.page >= data.total_pages;

  document.getElementById("policy-table-body").innerHTML = data.items
    .map(
      (p) => `
      <tr>
        <td>
          <strong>${esc(p.name)}</strong>
          ${p.conflict_reason ? `<div style="font-size:11.5px;color:var(--danger-text);margin-top:2px;">${esc(p.conflict_reason)}</div>` : ""}
        </td>
        <td>${esc(p.category)}</td>
        <td>
          <div><small>Inc: ${esc(p.assigned_include.join(", ") || "None (Orphan)")}</small></div>
          ${p.assigned_exclude.length ? `<div><small style="color:var(--warn-text);">Exc: ${esc(p.assigned_exclude.join(", "))}</small></div>` : ""}
        </td>
        <td>${esc(p.last_modified)}<br><small style="color:var(--muted);">${esc(p.modified_by)}</small></td>
        <td>${p.rfc_tag ? `<code>${esc(p.rfc_tag)}</code>` : `<span class="badge badge-danger">NONE</span>`}</td>
        <td>${statusBadge(p.status_flag)}</td>
      </tr>`
    )
    .join("");
}

function openControlModal(controlId) {
  const c = state.controls.find((x) => x.id === controlId);
  if (!c) return;
  document.getElementById("dlg-id").textContent = `${c.id} • ${c.cis_ref}`;
  document.getElementById("dlg-title").textContent = c.name;

  const polHtml = c.conflicting_policies.length
    ? c.conflicting_policies
        .map(
          (p) => `
          <div class="list-card">
            <div class="list-card-top"><div class="list-card-title">${esc(p.name)}</div>${statusBadge(p.status_flag)}</div>
            <div style="font-size:12px;color:var(--danger-text);">${esc(p.conflict_reason)}</div>
          </div>`
        )
        .join("")
    : `<p class="muted-note">No conflicting Intune policies detected.</p>`;

  document.getElementById("dlg-body").innerHTML = `
    <div class="kv-grid">
      <div class="kv-box"><strong>OIB Common-Sense Standard</strong>${esc(c.oib_value)}</div>
      <div class="kv-box"><strong>Strict CIS v5.0.0 Benchmark</strong>${esc(c.cis_value)}</div>
      <div class="kv-box"><strong>Microsoft 365 E7 License Fit</strong>${esc(c.e7_component)}</div>
      <div class="kv-box"><strong>Status / Coexistence Check</strong>${esc(c.diff_status)}</div>
    </div>
    <div class="kv-box" style="margin-bottom:14px;">
      <strong>Pre-Written Auditor Deviation Rationale</strong>
      ${esc(c.deviation_rationale)}
    </div>
    <div class="warning-box" style="margin-bottom:14px;">
      <strong>Production Breakage &amp; Coexistence Watchout (${esc(c.user_breakage_risk)} Risk — Start: ${esc(c.recommended_start_ring)}):</strong><br>
      ${esc(c.what_breaks_in_prod)}
    </div>
    <h3 style="margin:0 0 8px;font-size:14px;">Conflicting Policies (${c.conflicting_policies.length})</h3>
    <div class="stack-list">${polHtml}</div>`;
  document.getElementById("control-dialog").showModal();
}

function openRfcModal(controlId, action) {
  const c = state.controls.find((x) => x.id === controlId);
  if (!c) return;
  document.getElementById("rfc-control-id").value = controlId;
  document.getElementById("rfc-action").value = action;
  document.getElementById("rfc-dlg-title").textContent = `${action === "promote" ? "Promote" : "Rollback"} ${controlId}`;
  document.getElementById("rfc-summary").innerHTML =
    `<strong>${esc(c.name)}</strong><br>Current Ring: <code>${esc(c.current_ring)}</code>`;
  document.getElementById("rfc-note").value = "";
  document.getElementById("rfc-dialog").showModal();
}

function wireEvents() {
  document.getElementById("theme-toggle-btn").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(cur === "dark" ? "light" : "dark");
  });

  document.getElementById("pres-mode-btn").addEventListener("click", async () => {
    const next = state.envProfile?.presentation_mode === "ai_mcp" ? "classic_ops" : "ai_mcp";
    try {
      state.envProfile = await apiPost("/api/environment", { presentation_mode: next });
      applyPresentationMode();
      toast(next === "ai_mcp" ? "Switched to AI / MCP View." : "Switched to Classic Ops View (AI/MCP hidden).");
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.getElementById("env-profile-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await apiPost("/api/environment", {
        edr_provider: document.getElementById("env-edr").value,
        dlp_provider: document.getElementById("env-dlp").value,
        sccm_state: document.getElementById("env-sccm").value,
      });
      toast("Environment Stack Profile saved — Track 6 & 7 guardrails recalculated!");
      await refreshAll();
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.querySelectorAll(".subtab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const st = btn.dataset.subtab;
      document.querySelectorAll(".subtab-btn").forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.classList.toggle("btn-primary", b === btn);
        b.classList.toggle("btn-secondary", b !== btn);
      });
      document.querySelectorAll(".subtab-panel").forEach((p) => p.classList.toggle("active", p.id === `subtab-${st}`));
    });
  });

  document.getElementById("reset-sandbox-btn").addEventListener("click", async () => {
    try {
      await apiPost("/api/tenant/reset", {});
      toast("Restored 418-policy Synthetic Sandbox.");
      await refreshAll();
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.body.addEventListener("submit", async (ev) => {
    if (ev.target.id === "track-memory-form") {
      ev.preventDefault();
      try {
        await apiPost("/api/memory", {
          track_id: document.getElementById("mem-track-id").value,
          category: document.getElementById("mem-category").value,
          summary: document.getElementById("mem-summary").value,
          details: document.getElementById("mem-details").value,
          mark_track_complete: document.getElementById("mem-mark-done").checked,
        });
        toast("Saved to Tenant Context Memory & SHA-256 ITIL Audit Chain!");
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    }
  });

  document.body.addEventListener("click", async (ev) => {
    const openTrack = ev.target.closest("[data-open-track]");
    if (openTrack) {
      state.activeTrackId = openTrack.dataset.openTrack;
      state.activeTrackStep = 1;
      renderTracksView();
      return;
    }
    if (ev.target.id === "back-to-tracks" || ev.target.id === "back-to-tracks-bottom") {
      state.activeTrackId = null;
      renderTracksView();
      return;
    }
    const stepBtn = ev.target.closest("[data-track-step]");
    if (stepBtn) {
      state.activeTrackStep = Number(stepBtn.dataset.trackStep);
      renderTracksView();
      return;
    }
    if (ev.target.id === "copy-track-script") {
      await navigator.clipboard.writeText(document.getElementById("active-track-script")?.textContent || "");
      toast("PowerShell script copied to clipboard.");
      return;
    }
    const jumpBtn = ev.target.closest("[data-jump-tab]");
    if (jumpBtn) {
      const target = jumpBtn.dataset.jumpTab === "governance" ? "memory" : jumpBtn.dataset.jumpTab;
      switchTab(target);
      return;
    }
    const copyRawBtn = ev.target.closest("[data-copy-raw]");
    if (copyRawBtn && state.playbook) {
      const entry = state.playbook.scripts[copyRawBtn.dataset.copyRaw];
      if (entry) {
        await navigator.clipboard.writeText(entry.content);
        toast(`Copied ${entry.filename} to clipboard.`);
      }
      return;
    }
    if (ev.target.id === "snapshot-upload-btn") {
      const file = document.getElementById("snapshot-file-input")?.files?.[0];
      if (!file) {
        toast("Choose a JSON file exported by Export-IntuneGuardSnapshot.ps1 first.", true);
        return;
      }
      try {
        const parsed = JSON.parse(await file.text());
        await apiPost("/api/tenant/import", parsed);
        toast(`Imported real tenant snapshot from ${file.name}!`);
        switchTab("tracks");
        await refreshAll();
      } catch (err) {
        toast(`Snapshot import failed: ${err.message}`, true);
      }
      return;
    }
    if (ev.target.id === "gpo-upload-btn") {
      const file = document.getElementById("gpo-file-input")?.files?.[0];
      if (!file) {
        toast("Choose a GPMC XML file exported via Get-GPOReport -All -ReportType Xml.", true);
        return;
      }
      try {
        const xmlText = await file.text();
        const res = await apiPost("/api/gpo/import", { xml: xmlText });
        toast(`Scanned ${res.gpos_scanned} AD GPOs — found ${res.collisions_found} Intune collisions!`);
        await refreshAll();
      } catch (err) {
        toast(`GPO XML scan failed: ${err.message}`, true);
      }
      return;
    }
    const claimBtn = ev.target.closest("[data-claim-track]");
    if (claimBtn) {
      const owner = window.prompt("Enter your engineer email/UPN to claim this track:", "endpoint-architect@meridianfin.local");
      if (!owner) return;
      try {
        await apiPost("/api/tracks/claim", { track_id: claimBtn.dataset.claimTrack, owner });
        toast(`Track claimed by ${owner}.`);
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
      return;
    }
    const releaseBtn = ev.target.closest("[data-release-track]");
    if (releaseBtn) {
      try {
        await apiPost("/api/tracks/release", { track_id: releaseBtn.dataset.releaseTrack });
        toast("Track ownership lock released.");
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
      return;
    }
    const inspectBtn = ev.target.closest("[data-inspect]");
    if (inspectBtn) {
      openControlModal(inspectBtn.dataset.inspect);
      return;
    }
    const ringBtn = ev.target.closest("[data-ring-action]");
    if (ringBtn) {
      openRfcModal(ringBtn.dataset.cid, ringBtn.dataset.ringAction);
      return;
    }
    const copyBtn = ev.target.closest("[data-copy]");
    if (copyBtn) {
      await navigator.clipboard.writeText(document.getElementById(copyBtn.dataset.copy).textContent);
      toast("PowerShell remediation script copied to clipboard.");
      return;
    }
    const propBtn = ev.target.closest("[data-prop-decision]");
    if (propBtn) {
      try {
        await apiPost("/api/proposals/resolve", {
          proposal_id: propBtn.dataset.pid,
          decision: propBtn.dataset.propDecision,
          reviewer: "cab-approver@meridianfin.local",
        });
        toast(`Proposal ${propBtn.dataset.pid} ${propBtn.dataset.propDecision.toLowerCase()}.`);
        await refreshAll();
      } catch (err) {
        toast(err.message, true);
      }
    }
  });

  document.getElementById("dlg-close").addEventListener("click", () => document.getElementById("control-dialog").close());
  document.getElementById("rfc-cancel").addEventListener("click", () => document.getElementById("rfc-dialog").close());

  document.getElementById("rfc-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const payload = {
        control_id: document.getElementById("rfc-control-id").value,
        action: document.getElementById("rfc-action").value,
        rfc_ticket: document.getElementById("rfc-ticket").value,
        actor: document.getElementById("rfc-actor").value,
        note: document.getElementById("rfc-note").value,
      };
      const res = await apiPost("/api/rollout/transition", payload);
      document.getElementById("rfc-dialog").close();
      toast(`${payload.control_id} moved to ${res.rollout.current_ring}`);
      await refreshAll();
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.getElementById("backtrack-run-btn").addEventListener("click", () => runBacktrack());
  document.getElementById("backtrack-query").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runBacktrack();
  });
  document.getElementById("pol-search-btn").addEventListener("click", () => loadPolicies(1));
  document.getElementById("pol-status").addEventListener("change", () => loadPolicies(1));
  document.getElementById("pol-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadPolicies(1);
  });
  document.getElementById("pol-prev").addEventListener("click", () => loadPolicies(Math.max(1, state.policyPage - 1)));
  document.getElementById("pol-next").addEventListener("click", () => loadPolicies(state.policyPage + 1));
  document.getElementById("script-control-select").addEventListener("change", renderSelectedScript);

  document.getElementById("mcp-tool-select").addEventListener("change", (ev) => {
    const t = ev.target.value;
    const samples = {
      get_tenant_context_memory: {},
      audit_tenant_sprawl: {},
      evaluate_oib_cis_control: { control_id: "OIB-DEF-002" },
      resolve_nested_group_conflicts: {},
      generate_self_healing_remediation: { control_id: "OIB-UPD-007" },
      build_phased_ring_plan: { control_id: "OIB-ENC-001" },
      propose_policy_change: {
        control_id: "OIB-DEF-002",
        target_ring: "Ring 0 (Audit)",
        rfc_ticket: "CHG-2026-1099",
        justification: "Stage Defender ASR in Ring 0 Audit mode for 14-day branch peripheral telemetry soak.",
        actor: "endpoint-agent-apim@meridianfin.local",
      },
      backtrack_outage_timeline: { symptom: "bitlocker" },
      verify_itil_audit_chain: { limit: 10 },
    };
    document.getElementById("mcp-args-input").value = JSON.stringify(samples[t] || {}, null, 2);
  });

  document.getElementById("mcp-propose-sample-btn").addEventListener("click", () => {
    const sel = document.getElementById("mcp-tool-select");
    sel.value = "propose_policy_change";
    sel.dispatchEvent(new Event("change"));
  });

  document.getElementById("mcp-run-btn").addEventListener("click", async () => {
    const tool = document.getElementById("mcp-tool-select").value;
    let args = {};
    try {
      args = JSON.parse(document.getElementById("mcp-args-input").value || "{}");
    } catch {
      toast("Invalid JSON arguments.", true);
      return;
    }
    try {
      const rpc = await apiPost("/mcp", {
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: { name: tool, arguments: args },
      });
      document.getElementById("mcp-output").textContent = JSON.stringify(rpc, null, 2);
      toast(`MCP tool '${tool}' executed.`);
      await refreshAll();
    } catch (err) {
      toast(err.message, true);
    }
  });
}

initTheme();
wireEvents();
refreshAll();
