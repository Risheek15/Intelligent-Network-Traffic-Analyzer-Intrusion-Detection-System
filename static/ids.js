const POLL_INTERVAL_MS = 3000;

let cachedIncidents = [];
let expandedRowId = null;

const modelFilter = document.getElementById("filter-model");
const labelFilter = document.getElementById("filter-label");
const severityFilter = document.getElementById("filter-severity");
const verdictFilter = document.getElementById("filter-verdict");

if (modelFilter) modelFilter.addEventListener("change", renderIncidents);
if (labelFilter) labelFilter.addEventListener("change", renderIncidents);
if (severityFilter) severityFilter.addEventListener("change", renderIncidents);
if (verdictFilter) verdictFilter.addEventListener("change", renderIncidents);

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return isNaN(d.getTime()) ? "-" : d.toLocaleTimeString();
}

function formatModel(model) {
  if (!model) return "-";
  if (model === "isolation_forest" || model === "Isolation Forest") {
    return '<span class="badge badge-iso">Isolation Forest</span>';
  }
  if (model === "random_forest" || model === "Random Forest") {
    return '<span class="badge badge-rf">Random Forest</span>';
  }
  return `<span class="badge">${model}</span>`;
}

function formatLabel(label) {
  if (!label) return "-";
  const l = label.toLowerCase().trim();
  if (l === "anomaly") {
    return '<span class="badge-anomaly">Anomaly</span>';
  }
  let text = label;
  if (l === "dos") text = "DOS Flood";
  else if (l === "port_scan" || l === "port scan") text = "Port Scan";
  else if (l === "brute_force" || l === "brute force") text = "Brute Force";
  else text = label.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  return `<span class="badge-attack">${text}</span>`;
}

function formatSeverity(sev) {
  const s = (sev || "LOW").toUpperCase();
  if (s === "HIGH") {
    return '<span class="badge-sev badge-sev-high">HIGH</span>';
  }
  if (s === "MEDIUM") {
    return '<span class="badge-sev badge-sev-med">MED</span>';
  }
  return '<span class="badge-sev badge-sev-low">LOW</span>';
}

function formatConfidence(inc) {
  if (inc.confidence === null || inc.confidence === undefined) return "-";
  const sev = (inc.severity || "LOW").toUpperCase();
  let sevClass = "conf-sev-low";
  if (sev === "HIGH") sevClass = "conf-sev-high";
  else if (sev === "MEDIUM") sevClass = "conf-sev-med";

  if (inc.source_model === "random_forest") {
    const pct = (Number(inc.confidence) * 100).toFixed(1);
    return `<span class="${sevClass}">${pct}%</span>`;
  } else {
    const score = Number(inc.confidence).toFixed(3);
    return `<span class="${sevClass}">${score}</span>`;
  }
}

function formatVerdict(verdict) {
  if (!verdict) return '<span class="badge-pending">PENDING</span>';
  const v = verdict.toLowerCase().trim();
  if (v === "true_positive" || v === "true") {
    return '<span class="badge-true">TRUE</span>';
  }
  if (v === "false_positive" || v === "false") {
    return '<span class="badge-false">FALSE</span>';
  }
  return `<span class="badge">${verdict.toUpperCase()}</span>`;
}

function toggleExpandRow(id) {
  expandedRowId = (expandedRowId === id) ? null : id;
  renderIncidents();
}
window.toggleExpandRow = toggleExpandRow;

function copyFirewallCommand(btn, cmd) {
  navigator.clipboard.writeText(cmd).then(() => {
    const originalText = btn.textContent;
    btn.textContent = "✓ Copied PowerShell Rule!";
    btn.classList.add("btn-copied");
    setTimeout(() => {
      btn.textContent = originalText;
      btn.classList.remove("btn-copied");
    }, 2000);
  }).catch(err => {
    console.error("Clipboard copy failed:", err);
  });
}
window.copyFirewallCommand = copyFirewallCommand;

async function setVerdict(id, verdict, event) {
  if (event) event.stopPropagation();
  try {
    const res = await fetch(`/api/incidents/${id}/verdict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verdict }),
    });
    if (res.status === 401) {
      alert("Technician authentication required to submit verdicts.");
      window.location.href = "/login";
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.new_threshold !== undefined && data.new_threshold !== null) {
      const threshEl = document.getElementById("stat-threshold");
      if (threshEl) threshEl.textContent = Number(data.new_threshold).toFixed(3);
    }
    await refreshAll();
  } catch (err) {
    console.error("Failed to update verdict:", err);
  }
}
window.setVerdict = setVerdict;

function renderIncidents() {
  const tbody = document.querySelector("#incident-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const selModel = modelFilter ? modelFilter.value : "all";
  const selLabel = labelFilter ? labelFilter.value : "all";
  const selSeverity = severityFilter ? severityFilter.value : "all";
  const selVerdict = verdictFilter ? verdictFilter.value : "all";

  const filtered = (cachedIncidents || []).filter((inc) => {
    if (selModel !== "all" && inc.source_model !== selModel) return false;
    if (selLabel !== "all") {
      const l = (inc.label || "").toLowerCase().replace(/\s+/g, "_");
      if (l !== selLabel) return false;
    }
    if (selSeverity !== "all" && inc.severity !== selSeverity) return false;
    if (selVerdict !== "all") {
      if (selVerdict === "pending" && inc.verdict) return false;
      if (selVerdict === "true_positive" && inc.verdict !== "true_positive") return false;
      if (selVerdict === "false_positive" && inc.verdict !== "false_positive") return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    const isFiltered = (selModel !== "all" || selLabel !== "all" || selSeverity !== "all" || selVerdict !== "all");
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align: center; padding: 48px 20px;">
          <div style="font-size: 2rem; margin-bottom: 8px;">🛡️</div>
          <strong style="color: #ffffff; font-size: 1rem; letter-spacing: 0.02em;">
            ${isFiltered ? "No Matching Incidents" : "All Clear — No Threats Detected"}
          </strong>
          <div style="font-size: 0.85rem; margin-top: 6px; color: var(--muted);">
            ${isFiltered ? "No events match your current filter selection." : "Your network traffic is safe. No intrusions or anomalies found."}
          </div>
        </td>
      </tr>
    `;
    return;
  }

  filtered.forEach((inc) => {
    const isRF = (inc.source_model === "random_forest");
    const isExpanded = (expandedRowId === inc.id);

    const mainTr = document.createElement("tr");
    mainTr.className = isRF ? "incident-row-rf clickable-row" : "incident-row-iso";
    if (isRF) {
      mainTr.title = "Click to view suggested action & PowerShell mitigation command";
      mainTr.onclick = () => toggleExpandRow(inc.id);
    }

    const threatDisplay = formatLabel(inc.label) + (isRF ? ' <span class="expand-hint">▼</span>' : '');

    mainTr.innerHTML = `
      <td>${fmtTime(inc.timestamp)}</td>
      <td>${threatDisplay}</td>
      <td>${formatSeverity(inc.severity)}</td>
      <td>${formatConfidence(inc)}</td>
      <td><span class="ip-mono ip-attacker">${inc.src_ip || "-"}</span></td>
      <td><span class="ip-mono">${inc.dst_ip || "-"}:${inc.dst_port || "-"}</span></td>
      <td>${formatModel(inc.source_model)}</td>
      <td>${formatVerdict(inc.verdict)}</td>
      <td>
        <button class="verdict-btn true-btn" onclick="setVerdict(${inc.id}, 'true_positive', event)">True</button>
        <button class="verdict-btn false-btn" onclick="setVerdict(${inc.id}, 'false_positive', event)">False</button>
      </td>
    `;
    tbody.appendChild(mainTr);

    // If expanded and is Random Forest attack: Render the Remediation Card row
    if (isRF && isExpanded) {
      const detailTr = document.createElement("tr");
      detailTr.className = "detail-expansion-row";
      const cmdText = inc.firewall_cmd || `New-NetFirewallRule -DisplayName "IDS_Block_${inc.src_ip}" -Direction Inbound -Action Block -RemoteAddress "${inc.src_ip}"`;

      detailTr.innerHTML = `
        <td colspan="9">
          <div class="remediation-panel">
            <div class="remediation-header">
              <span class="rem-title">🚨 Threat Diagnosis & Remediation Playbook</span>
              <span class="rem-target">Target Service: <strong>${inc.dst_port || "Unknown Port"} (${inc.protocol || "TCP"})</strong></span>
            </div>
            <div class="rem-action-text">
              <strong>Suggested Action:</strong> ${inc.suggested_action || "Block incoming connections from this attacker IP to secure the host."}
            </div>
            <div class="rem-code-box">
              <div class="rem-code-label">PowerShell Mitigation Command (Run as Administrator):</div>
              <div class="rem-code-row">
                <code>${cmdText}</code>
                <button class="copy-cmd-btn" onclick="copyFirewallCommand(this, '${cmdText}')">📋 Copy PowerShell Command</button>
              </div>
            </div>
          </div>
        </td>
      `;
      tbody.appendChild(detailTr);
    }
  });
}

async function refreshSummary() {
  const summary = await fetchJSON("/api/summary");
  const threshEl = document.getElementById("stat-threshold");
  if (threshEl && summary.iso_threshold !== undefined) {
    threshEl.textContent = Number(summary.iso_threshold).toFixed(3);
  }
}

async function refreshIncidents() {
  try {
    cachedIncidents = await fetchJSON("/api/incidents?limit=500");
    
    // Update metric cards
    const totalCount = cachedIncidents.length;
    const rfCount = cachedIncidents.filter(i => i.source_model === "random_forest").length;
    const isoCount = cachedIncidents.filter(i => i.source_model === "isolation_forest").length;

    const totalEl = document.getElementById("ids-total-incidents");
    const rfEl = document.getElementById("ids-rf-attacks");
    const isoEl = document.getElementById("ids-iso-anomalies");

    if (totalEl) totalEl.textContent = totalCount;
    if (rfEl) rfEl.textContent = rfCount;
    if (isoEl) isoEl.textContent = isoCount;

    renderIncidents();
  } catch (err) {
    console.error("Incidents error:", err);
  }
}

async function clearIncidentLog() {
  if (!confirm("Are you sure you want to clear the entire security incident log?")) {
    return;
  }
  try {
    const res = await fetch("/api/incidents/clear", { method: "POST" });
    if (res.status === 401) {
      alert("Technician authentication required to clear incident log.");
      return;
    }
    await refreshAll();
  } catch (err) {
    console.error("Failed to clear incident log:", err);
  }
}
window.clearIncidentLog = clearIncidentLog;

async function refreshAll() {
  try { await refreshSummary(); } catch (err) { console.error("Summary error:", err); }
  try { await refreshIncidents(); } catch (err) { console.error("Incidents error:", err); }
}

refreshAll();
setInterval(refreshAll, POLL_INTERVAL_MS);
