const POLL_INTERVAL_MS = 3000;

let currentChartMode = "packets"; // "packets" or "bytes"
let lastSeenWindowId = 0;
let cachedWindows = [];

const trafficCtx = document.getElementById("trafficChart").getContext("2d");
const protocolCtx = document.getElementById("protocolChart").getContext("2d");

const trafficChart = new Chart(trafficCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [{
      label: "Packets per window",
      data: [],
      borderColor: "#ffffff",
      backgroundColor: "rgba(255, 255, 255, 0.08)",
      borderWidth: 1.5,
      tension: 0.3,
      fill: true,
      pointRadius: 2,
    }],
  },
  options: {
    responsive: true,
    scales: {
      x: { ticks: { color: "#a0a0a0" }, grid: { color: "#222222" } },
      y: { ticks: { color: "#a0a0a0" }, grid: { color: "#222222" } },
    },
    plugins: { legend: { labels: { color: "#ffffff" } } },
  },
});

const protocolChart = new Chart(protocolCtx, {
  type: "doughnut",
  data: {
    labels: ["TCP", "UDP", "ICMP"],
    datasets: [{
      data: [0, 0, 0],
      backgroundColor: ["#c0c0c0", "#7a7a7a", "#484848"],
      borderWidth: 1,
      borderColor: "#181818",
    }],
  },
  options: {
    responsive: true,
    plugins: { legend: { labels: { color: "#ffffff" } } },
  },
});

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

function setChartMode(mode) {
  currentChartMode = mode;
  const btnPackets = document.getElementById("mode-packets-btn");
  const btnBytes = document.getElementById("mode-bytes-btn");
  const chartTitle = document.getElementById("chart-title");

  if (mode === "packets") {
    if (btnPackets) btnPackets.classList.add("active");
    if (btnBytes) btnBytes.classList.remove("active");
    if (chartTitle) chartTitle.textContent = "Packet Rate Over Time";
    trafficChart.data.datasets[0].label = "Packets per window";
  } else {
    if (btnBytes) btnBytes.classList.add("active");
    if (btnPackets) btnPackets.classList.remove("active");
    if (chartTitle) chartTitle.textContent = "Bandwidth Throughput Over Time (KB/s)";
    trafficChart.data.datasets[0].label = "Throughput (KB/s)";
  }
  renderTrafficChart();
}
window.setChartMode = setChartMode;

function renderTrafficChart() {
  const ordered = (cachedWindows || []).slice().reverse();
  trafficChart.data.labels = ordered.map((w) => fmtTime(w.timestamp));

  if (currentChartMode === "packets") {
    trafficChart.data.datasets[0].data = ordered.map((w) => w.packet_count ?? 0);
  } else {
    // 5-second window: throughput in KB/s = bytes / 1024 / 5.0
    trafficChart.data.datasets[0].data = ordered.map((w) => {
      const bytes = w.byte_count ?? 0;
      return Number((bytes / 1024 / 5.0).toFixed(1));
    });
  }
  trafficChart.update();
}

async function refreshSummary() {
  const summary = await fetchJSON("/api/summary");
  document.getElementById("stat-windows").textContent = summary.windows_seen ?? 0;
  document.getElementById("stat-packets").textContent = summary.total_packets ?? 0;

  // Format bytes nicely (KB, MB, GB)
  const totalB = summary.total_bytes ?? 0;
  let formattedBytes = totalB + " B";
  if (totalB >= 1073741824) formattedBytes = (totalB / 1073741824).toFixed(2) + " GB";
  else if (totalB >= 1048576) formattedBytes = (totalB / 1048576).toFixed(2) + " MB";
  else if (totalB >= 1024) formattedBytes = (totalB / 1024).toFixed(1) + " KB";
  document.getElementById("stat-bytes").textContent = formattedBytes;

  document.getElementById("stat-incidents").textContent = summary.incident_count ?? 0;

  if (summary.protocol_mix) {
    protocolChart.data.datasets[0].data = [
      summary.protocol_mix.tcp ?? 0,
      summary.protocol_mix.udp ?? 0,
      summary.protocol_mix.icmp ?? 0,
    ];
    protocolChart.update();
  }
}

let streamRecords = [];
let pktsSliderCtrl = null;
let sizeSliderCtrl = null;
let flowsSliderCtrl = null;

function initDualSlider({
  minSliderId,
  maxSliderId,
  minNumId,
  maxNumId,
  fillId,
  pillId,
  trackId,
  unit,
  maxLimit
}) {
  const minSlider = document.getElementById(minSliderId);
  const maxSlider = document.getElementById(maxSliderId);
  const minNum = document.getElementById(minNumId);
  const maxNum = document.getElementById(maxNumId);
  const fill = document.getElementById(fillId);
  const pill = document.getElementById(pillId);
  const track = document.getElementById(trackId);

  if (!minSlider || !maxSlider || !fill || !pill) {
    return { reset: () => {} };
  }

  function update(source) {
    let minVal = Number(minSlider.value);
    let maxVal = Number(maxSlider.value);

    if (minVal > maxVal) {
      if (source === "min") {
        minVal = maxVal;
        minSlider.value = minVal;
      } else {
        maxVal = minVal;
        maxSlider.value = maxVal;
      }
    }

    if (minNum && minNum !== document.activeElement) minNum.value = minVal;
    if (maxNum && maxNum !== document.activeElement) maxNum.value = maxVal;

    const minLimit = Number(minSlider.min) || 0;
    const maxBound = Number(minSlider.max) || maxLimit;
    const leftPct = ((minVal - minLimit) / (maxBound - minLimit)) * 100;
    const rightPct = ((maxVal - minLimit) / (maxBound - minLimit)) * 100;

    fill.style.left = `${leftPct}%`;
    fill.style.width = `${Math.max(0, rightPct - leftPct)}%`;

    const isAll = (minVal <= minLimit && maxVal >= maxBound);
    const maxStr = (maxVal >= maxBound) ? `${maxBound.toLocaleString()}+` : maxVal.toLocaleString();

    if (isAll) {
      pill.textContent = `All (0 – ${maxStr} ${unit})`;
      pill.classList.remove("slider-pill-active");
    } else {
      pill.textContent = `${minVal.toLocaleString()} – ${maxStr} ${unit}`;
      pill.classList.add("slider-pill-active");
    }

    renderStream();
  }

  minSlider.addEventListener("input", () => {
    minSlider.style.zIndex = 5;
    maxSlider.style.zIndex = 4;
    update("min");
  });

  maxSlider.addEventListener("input", () => {
    maxSlider.style.zIndex = 5;
    minSlider.style.zIndex = 4;
    update("max");
  });

  if (minNum) {
    minNum.addEventListener("input", () => {
      let val = Number(minNum.value);
      if (isNaN(val) || val < 0) val = 0;
      if (val > Number(maxSlider.value)) val = Number(maxSlider.value);
      minSlider.value = val;
      update("min");
    });
  }

  if (maxNum) {
    maxNum.addEventListener("input", () => {
      let val = Number(maxNum.value);
      if (isNaN(val)) val = maxLimit;
      if (val < Number(minSlider.value)) val = Number(minSlider.value);
      if (val > maxLimit) val = maxLimit;
      maxSlider.value = val;
      update("max");
    });
  }

  if (track) {
    track.addEventListener("pointerdown", (e) => {
      const rect = track.getBoundingClientRect();
      const clickPct = (e.clientX - rect.left) / rect.width;
      const minLimit = Number(minSlider.min) || 0;
      const maxBound = Number(minSlider.max) || maxLimit;
      const clickVal = minLimit + clickPct * (maxBound - minLimit);

      const dMin = Math.abs(clickVal - Number(minSlider.value));
      const dMax = Math.abs(clickVal - Number(maxSlider.value));

      if (dMin <= dMax) {
        minSlider.style.zIndex = 5;
        maxSlider.style.zIndex = 4;
      } else {
        maxSlider.style.zIndex = 5;
        minSlider.style.zIndex = 4;
      }
    });
  }

  update();

  return {
    reset: () => {
      minSlider.value = 0;
      maxSlider.value = maxLimit;
      if (minNum) minNum.value = 0;
      if (maxNum) maxNum.value = maxLimit;
      update();
    }
  };
}

function resetStreamFilters() {
  const p = document.getElementById("stream-proto-filter");
  const s = document.getElementById("stream-src-filter");
  const d = document.getElementById("stream-dst-filter");

  if (p) p.value = "all";
  if (s) s.value = "";
  if (d) d.value = "";

  if (pktsSliderCtrl) pktsSliderCtrl.reset();
  if (sizeSliderCtrl) sizeSliderCtrl.reset();
  if (flowsSliderCtrl) flowsSliderCtrl.reset();

  renderStream();
}
window.resetStreamFilters = resetStreamFilters;

function renderStream() {
  const terminal = document.getElementById("flow-terminal");
  if (!terminal) return;

  const protoFilter = (document.getElementById("stream-proto-filter")?.value || "all").toUpperCase();
  const srcFilter = (document.getElementById("stream-src-filter")?.value || "").trim().toLowerCase();
  const dstFilter = (document.getElementById("stream-dst-filter")?.value || "").trim().toLowerCase();

  const minPkts = Number(document.getElementById("pkts-min")?.value || 0);
  const maxPkts = Number(document.getElementById("pkts-max")?.value || 10000);

  const minSize = Number(document.getElementById("size-min")?.value || 0);
  const maxSize = Number(document.getElementById("size-max")?.value || 10000);

  const minFlows = Number(document.getElementById("flows-min")?.value || 0);
  const maxFlows = Number(document.getElementById("flows-max")?.value || 500);

  const filtered = streamRecords.filter(r => {
    // 1. Protocol filter
    if (protoFilter !== "ALL" && r.proto !== protoFilter) return false;

    // 2. Source IP filter
    if (srcFilter && !String(r.srcIp).toLowerCase().includes(srcFilter)) return false;

    // 3. Destination IP / Port filter
    if (dstFilter) {
      const dstStr = `${r.dstIp}:${r.dstPort}`.toLowerCase();
      if (!dstStr.includes(dstFilter)) return false;
    }

    // 4. Packets lower and upper sliding limit
    const p = Number(r.pkts) || 0;
    if (minPkts > 0 && p < minPkts) return false;
    if (maxPkts < 10000 && p > maxPkts) return false;

    // 5. Size (KB) lower and upper sliding limit
    const s = Number(r.kb) || 0;
    if (minSize > 0 && s < minSize) return false;
    if (maxSize < 10000 && s > maxSize) return false;

    // 6. Network Flows lower and upper sliding limit
    const f = Number(r.flows) || 0;
    if (minFlows > 0 && f < minFlows) return false;
    if (maxFlows < 500 && f > maxFlows) return false;

    return true;
  });

  if (filtered.length === 0) {
    terminal.innerHTML = '<div class="terminal-placeholder">No live network flows match current filter.</div>';
    return;
  }

  terminal.innerHTML = "";
  filtered.forEach(r => {
    let protoClass = "term-proto-tcp";
    if (r.proto === "UDP") protoClass = "term-proto-udp";
    else if (r.proto === "ICMP") protoClass = "term-proto-icmp";

    const line = document.createElement("div");
    line.className = "terminal-line";
    line.innerHTML = `
      <span class="term-time">[${r.timeStr}]</span>
      <span class="term-proto ${protoClass}">${r.proto}</span>
      <span class="term-ip-src">${r.srcIp}</span>
      <span class="term-arrow">→</span>
      <span class="term-ip-dst">${r.dstIp}:${r.dstPort}</span>
      <span class="term-metric">${r.pkts} pkts</span>
      <span class="term-metric">${r.kb} KB</span>
      <span class="term-metric">${r.flows} flows</span>
    `;
    terminal.appendChild(line);
  });
}
window.renderStream = renderStream;

function updateFlowStream(windows) {
  const newWindows = (windows || []).filter(w => w.id > lastSeenWindowId);
  if (newWindows.length === 0) return;

  newWindows.forEach(w => {
    if (w.id > lastSeenWindowId) lastSeenWindowId = w.id;

    const feats = w.features || {};
    const srcIp = feats.src_ip || "172.17.108.16";
    const dstIp = feats.dst_ip || "-";
    const dstPort = feats.dst_port || "-";
    const proto = (feats.protocol || "TCP").toUpperCase();
    const pkts = w.packet_count ?? 0;
    const kb = ((w.byte_count ?? 0) / 1024).toFixed(1);
    const flows = feats.distinct_flows ?? "-";

    streamRecords.unshift({
      id: w.id,
      timeStr: fmtTime(w.timestamp),
      proto,
      srcIp,
      dstIp,
      dstPort,
      pkts,
      kb,
      flows,
    });

    if (streamRecords.length > 50) {
      streamRecords.pop();
    }
  });

  renderStream();
}

function clearStreamLog() {
  streamRecords = [];
  renderStream();
}
window.clearStreamLog = clearStreamLog;

async function refreshTraffic() {
  cachedWindows = await fetchJSON("/api/windows?limit=30");
  renderTrafficChart();
  updateFlowStream(cachedWindows);
}

async function clearTrafficData() {
  if (!confirm("Reset all recorded traffic graph data?")) {
    return;
  }
  try {
    const res = await fetch("/api/traffic/clear", { method: "POST" });
    if (res.status === 401) {
      alert("Technician authentication required to reset traffic graph.");
      return;
    }
    clearStreamLog();
    await refreshAll();
  } catch (err) {
    console.error("Failed to reset traffic data:", err);
  }
}
window.clearTrafficData = clearTrafficData;

async function refreshAll() {
  try { await refreshSummary(); } catch (err) { console.error("Summary error:", err); }
  try { await refreshTraffic(); } catch (err) { console.error("Traffic error:", err); }
}

// Initialize sliding range bar controllers
pktsSliderCtrl = initDualSlider({
  minSliderId: "pkts-min",
  maxSliderId: "pkts-max",
  minNumId: "pkts-min-num",
  maxNumId: "pkts-max-num",
  fillId: "fill-pkts",
  pillId: "pkts-pill",
  trackId: "track-pkts",
  unit: "pkts",
  maxLimit: 10000
});

sizeSliderCtrl = initDualSlider({
  minSliderId: "size-min",
  maxSliderId: "size-max",
  minNumId: "size-min-num",
  maxNumId: "size-max-num",
  fillId: "fill-size",
  pillId: "size-pill",
  trackId: "track-size",
  unit: "KB",
  maxLimit: 10000
});

flowsSliderCtrl = initDualSlider({
  minSliderId: "flows-min",
  maxSliderId: "flows-max",
  minNumId: "flows-min-num",
  maxNumId: "flows-max-num",
  fillId: "fill-flows",
  pillId: "flows-pill",
  trackId: "track-flows",
  unit: "flows",
  maxLimit: 500
});

refreshAll();
setInterval(refreshAll, POLL_INTERVAL_MS);
