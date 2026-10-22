function scoreColor(score) {
  if (score >= 60) return "#D32F2F";
  if (score >= 30) return "#F9A825";
  return "#4CAF50";
}

function timeAgo(ts) {
  if (!ts) return "—";
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

function fullTime(ts) {
  return new Date(ts).toLocaleString();
}

const TYPE_LABELS = {
  suspicious_connection: "Connection",
  score_threshold: "Score",
  vt_scan: "VirusTotal",
  system_cpu_high: "System"
};

// ---------- System resources (live-sampled while this tab is open) ----------
let lastDashCpuSample = null;

async function sampleSystemCpuPercent() {
  try {
    const info = await chrome.system.cpu.getInfo();
    const processors = info.processors.map(p => ({ ...p.usage }));
    let percent = null;
    if (lastDashCpuSample && lastDashCpuSample.length === processors.length) {
      let used = 0, total = 0;
      processors.forEach((p, i) => {
        const prev = lastDashCpuSample[i];
        const dTotal = p.total - prev.total;
        const dIdle = p.idle - prev.idle;
        if (dTotal > 0) { used += (dTotal - dIdle); total += dTotal; }
      });
      percent = total > 0 ? Math.round((used / total) * 100) : null;
    }
    lastDashCpuSample = processors;
    return percent;
  } catch (e) {
    return null;
  }
}

function fmtBytes(n) {
  if (!n) return "0";
  return (n / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

async function refreshSystemUsage() {
  const cpuEl = document.getElementById("sysCpu");
  const percent = await sampleSystemCpuPercent();
  cpuEl.textContent = percent == null ? "—" : `${percent}%`;
  cpuEl.style.color = percent == null ? "" : scoreColor(percent);

  const memEl = document.getElementById("sysMem");
  try {
    const memInfo = await chrome.system.memory.getInfo();
    const used = memInfo.capacity - memInfo.availableCapacity;
    memEl.textContent = `${fmtBytes(used)} / ${fmtBytes(memInfo.capacity)}`;
  } catch (e) {
    memEl.textContent = "—";
  }
}

// ---------- Shared state ----------
// Cached copies of the last fetched data, so clicking a tab to filter can
// re-render instantly from what's already on screen instead of re-fetching.
let lastStates = [];
let lastLog = [];
let lastVtResults = [];
let currentFilter = "all";     // event log type filter: all / suspicious_connection / etc.
let selectedTab = null;        // the tab state object currently clicked, or null for "all tabs"

// ---------- Click-a-tab-to-filter ----------
function tabRelevantIndicators(state) {
  const set = new Set();
  if (!state) return set;
  if (state.hostname) set.add(state.hostname);
  Object.entries(state.requestsByHost || {}).forEach(([host, rec]) => {
    set.add(host);
    (rec.ips || []).forEach(ip => set.add(ip));
  });
  return set;
}

function updateFilterBadge() {
  const badge = document.getElementById("tabFilterBadge");
  if (!badge) return;
  if (selectedTab) {
    badge.style.display = "inline-flex";
    badge.innerHTML = `Filtered to: ${selectedTab.hostname || "this tab"} <button id="clearTabFilterBtn" title="Clear filter">✕</button>`;
    document.getElementById("clearTabFilterBtn").addEventListener("click", (e) => {
      e.stopPropagation();
      clearTabFilter();
    });
  } else {
    badge.style.display = "none";
    badge.innerHTML = "";
  }
}

function applyTabSelection() {
  updateFilterBadge();
  renderTabs(lastStates);         // re-render to update row highlight
  renderVtResults(lastVtResults); // re-filter from cache, no re-fetch
  renderLog(lastLog);             // re-filter from cache, no re-fetch
}

function selectTab(tabId) {
  if (selectedTab && selectedTab.tabId === tabId) {
    selectedTab = null; // clicking the already-selected row again clears the filter
  } else {
    selectedTab = lastStates.find(s => s.tabId === tabId) || null;
  }
  applyTabSelection();
}

function clearTabFilter() {
  selectedTab = null;
  applyTabSelection();
}

// ---------- Refresh button feedback ----------
// Gives a click something visible to react to: the button disables and says
// "Refreshing…", then the panel briefly flashes once new data is in, so it's
// obvious the click actually did something even if the numbers didn't change.
function flashPanel(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove("flash");
  void el.offsetWidth; // force reflow so re-adding the class restarts the animation
  el.classList.add("flash");
}

async function withButtonFeedback(btn, fn) {
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Refreshing…";
  try {
    await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

// ---------- Tracked tabs ----------
function renderTabs(states) {
  lastStates = states || [];
  const body = document.getElementById("tabsBody");
  if (!lastStates.length) {
    body.innerHTML = '<tr><td colspan="8" class="empty">No tabs tracked yet — browse to a site to start collecting signals.</td></tr>';
    return;
  }
  const sorted = lastStates.slice().sort((a, b) => (b.score || 0) - (a.score || 0));
  body.innerHTML = sorted.map(s => {
    const t = s.telemetry || {};
    const susWs = (t.websockets || []).filter(w => w.suspicious).length;
    const isSelected = selectedTab && selectedTab.tabId === s.tabId;
    return `
      <tr data-tab-id="${s.tabId}" class="${isSelected ? "selected-tab" : ""}" title="Click to filter VirusTotal results and the event log to this tab">
        <td><span class="score-pill" style="background:${scoreColor(s.score || 0)}">${s.score || 0}</span></td>
        <td>
          <div class="host-cell">${s.hostname || "(unknown)"}</div>
          <div class="url-cell">${s.url || ""}</div>
        </td>
        <td>${t.wasmInstantiations || 0}</td>
        <td>${t.workersCreated || 0}</td>
        <td>${susWs}</td>
        <td>${Math.round(t.longTaskTotalMs || 0)}</td>
        <td>${(s.suspiciousConnections || []).length}</td>
        <td class="muted" title="${fullTime(s.lastUpdated)}">${timeAgo(s.lastUpdated)}</td>
      </tr>`;
  }).join("");
}

function refreshTabs() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_ALL_STATES" }, (resp) => {
      renderTabs(resp?.states || []);
      resolve();
    });
  });
}

document.getElementById("tabsBody").addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-tab-id]");
  if (!row) return;
  selectTab(Number(row.dataset.tabId));
});

document.getElementById("refreshTabsBtn").addEventListener("click", async () => {
  const btn = document.getElementById("refreshTabsBtn");
  await withButtonFeedback(btn, refreshTabs);
  flashPanel("tabsPanel");
});

// ---------- VirusTotal results ----------
function fmtChecked(ts) {
  return ts ? timeAgo(ts) : "—";
}

function renderVtResults(results) {
  lastVtResults = results || lastVtResults;
  const body = document.getElementById("vtBody");
  const relevant = selectedTab ? tabRelevantIndicators(selectedTab) : null;
  const filtered = relevant ? lastVtResults.filter(r => relevant.has(r.indicator)) : lastVtResults;

  if (!filtered.length) {
    body.innerHTML = selectedTab
      ? `<tr><td colspan="7" class="empty">No VirusTotal checks yet for ${selectedTab.hostname || "this tab"}.</td></tr>`
      : '<tr><td colspan="7" class="empty">No VirusTotal checks yet — click "Check top hosts / IPs with VirusTotal" in the popup on any tab.</td></tr>';
    return;
  }
  body.innerHTML = filtered.map(r => {
    if (r.notFound) {
      return `
        <tr>
          <td class="host-cell">${r.indicator}</td>
          <td>${r.type || ""}</td>
          <td colspan="4" class="muted">Not in VirusTotal's dataset</td>
          <td class="muted" title="${fullTime(r.checkedAt)}">${fmtChecked(r.checkedAt)}</td>
        </tr>`;
    }
    const s = r.stats || {};
    const mal = s.malicious || 0, sus = s.suspicious || 0;
    const rowClass = mal > 0 ? "critical" : (sus > 0 ? "elevated" : "");
    const chip = mal > 0 ? '<span class="sev-chip critical">CRITICAL</span>' : (sus > 0 ? '<span class="sev-chip elevated">SUSPICIOUS</span>' : "");
    return `
      <tr class="vt-row ${rowClass}">
        <td class="host-cell">${r.indicator}${chip}</td>
        <td>${r.type || ""}</td>
        <td>${mal}</td>
        <td>${sus}</td>
        <td>${s.harmless || 0}</td>
        <td>${s.undetected || 0}</td>
        <td class="muted" title="${fullTime(r.checkedAt)}">${fmtChecked(r.checkedAt)}</td>
      </tr>`;
  }).join("");
}

function refreshVt() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_VT_RESULTS" }, (resp) => {
      renderVtResults(resp?.results || []);
      resolve();
    });
  });
}

document.getElementById("refreshVtBtn").addEventListener("click", async () => {
  const btn = document.getElementById("refreshVtBtn");
  await withButtonFeedback(btn, refreshVt);
  flashPanel("vtPanel");
});

// ---------- Event log ----------
function renderLog(log) {
  lastLog = log || lastLog;
  const list = document.getElementById("logList");
  let filtered = currentFilter === "all" ? lastLog : lastLog.filter(e => e.type === currentFilter);
  if (selectedTab) {
    filtered = filtered.filter(e =>
      (selectedTab.tabId != null && e.tabId === selectedTab.tabId) ||
      (selectedTab.hostname && e.hostname === selectedTab.hostname)
    );
  }

  if (!filtered.length) {
    list.innerHTML = selectedTab
      ? `<div class="empty">No matching events for ${selectedTab.hostname || "this tab"}.</div>`
      : '<div class="empty">No events logged yet.</div>';
    return;
  }
  list.innerHTML = filtered.map(e => `
    <div class="log-row${e.severity === "critical" ? " critical" : ""}">
      <div class="log-ts" title="${fullTime(e.ts)}">${timeAgo(e.ts)}</div>
      <div class="log-type ${e.type}">${TYPE_LABELS[e.type] || e.type}${e.severity === "critical" ? '<span class="sev-chip critical">CRITICAL</span>' : ""}</div>
      <div class="log-host">${e.hostname || "(unknown)"}</div>
      <div class="log-detail">${e.detail || ""}</div>
    </div>`).join("");
}

function refreshLog() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_EVENT_LOG" }, (resp) => {
      renderLog(resp?.log || []);
      resolve();
    });
  });
}

document.getElementById("refreshLogBtn").addEventListener("click", async () => {
  const btn = document.getElementById("refreshLogBtn");
  await withButtonFeedback(btn, refreshLog);
  flashPanel("logPanel");
});

document.getElementById("clearLogBtn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_EVENT_LOG" }, () => {
    refreshLog();
  });
});

document.getElementById("logFilters").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-filter]");
  if (!btn) return;
  currentFilter = btn.dataset.filter;
  document.querySelectorAll("#logFilters button").forEach(b => b.classList.toggle("active", b === btn));
  renderLog(lastLog);
});

// ---------- Boot ----------
refreshTabs();
refreshLog();
refreshSystemUsage();
refreshVt();
setInterval(refreshTabs, 4000);
setInterval(refreshLog, 5000);
setInterval(refreshSystemUsage, 3000);
setInterval(refreshVt, 6000);
