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
  system_cpu_high: "System",
  static_scan: "Static scan",
  dynamic_behavior: "Dynamic"
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
function l1Chip(l1) {
  if (!l1 || l1.disabled || !l1.scannedAt) return '<span class="l1-chip none">—</span>';
  const label = l1.level === "strong" ? "Strong signs" : l1.level === "possible" ? "Possible" : "Clear";
  return `<span class="l1-chip ${l1.level}">${label}</span>`;
}

function renderTabs(states) {
  lastStates = states || [];
  const body = document.getElementById("tabsBody");
  if (!lastStates.length) {
    body.innerHTML = '<tr><td colspan="9" class="empty">No tabs tracked yet — browse to a site to start collecting signals.</td></tr>';
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
        <td>${l1Chip(s.layer1)}</td>
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










// // ===== JackTrap — background service worker =====
// // NOTE (important limitation): a browser extension has NO API to enumerate
// // OS-level processes, per-process CPU/RAM, or hash a running executable.
// // Everything here is derived from what the browser itself can observe:
// // network requests per tab, and in-page JS behavior signals relayed from
// // page-hook.js (WASM use, Worker/WebSocket creation, long-task blocking,
// // JS heap growth). That's the ceiling of what's possible without a native
// // helper app talking to the OS.

// /* global SIGNATURES, SETTINGS_KEY, loadSettings, activeSignatures, scanSources, mergeHitMaps,
//    summarize, emptyLayer1, isFetchableUrl, isThirdParty, LAYER1_LIMITS,
//    emptyLayer2, mergeDynamic, metricsToMap, processFromSeries, processFromNative, scoreLayer2 */
// importScripts("signatures.js", "layer1.js", "layer2.js", "settings.js");

// const SUSPICIOUS_PORTS = new Set([
//   3333, 3357, 4444, 4028, 5555, 5730, 7777, 8080, 8118, 8888,
//   9999, 14444, 14433, 45560, 45700
// ]);
// const MINING_KEYWORDS = [
//   "xmr", "monero", "stratum", "cryptonight", "nanopool", "minexmr",
//   "supportxmr", "webmine", "coinimp", "crypto-loot", "cryptoloot",
//   "authedmine", "coinhive", "minero", "jsecoin", "webminepool", "hashvault"
// ];

// const tabStates = new Map(); // tabId -> state

// // ---------- Persistent event log (backs the full-dashboard tab) ----------
// // tabStates is in-memory only and resets on navigation/SW restart, so
// // anything worth reviewing later (a suspicious connection, a score jumping
// // into "elevated"/"high", a VT scan result) also gets written here, to
// // chrome.storage.local, capped at EVENT_LOG_MAX entries.
// const EVENT_LOG_KEY = "jacktrap_eventLog";
// const EVENT_LOG_MAX = 300;

// // Serialized so concurrent callers (e.g. a suspicious_connection firing at
// // the same moment a vt_scan finishes) can't race: read-modify-write on the
// // same storage key from two calls at once would let the second overwrite
// // the first, silently dropping an entry.
// let logWriteTail = Promise.resolve();
// function addLogEntry(entry) {
//   const run = logWriteTail.then(async () => {
//     try {
//       const store = await chrome.storage.local.get(EVENT_LOG_KEY);
//       const log = store[EVENT_LOG_KEY] || [];
//       log.push({ ts: Date.now(), ...entry });
//       if (log.length > EVENT_LOG_MAX) log.splice(0, log.length - EVENT_LOG_MAX);
//       await chrome.storage.local.set({ [EVENT_LOG_KEY]: log });
//     } catch (e) {}
//   });
//   logWriteTail = run.catch(() => {});
//   return run;
// }

// function scoreTier(score) {
//   if (score >= 60) return "high";
//   if (score >= 30) return "elevated";
//   if (score > 0) return "low";
//   return "none";
// }

// // Logs a score-threshold crossing at most once per tier, per navigation.
// function maybeLogScoreTier(state) {
//   const tier = scoreTier(state.score);
//   if (tier !== state.lastLoggedTier && (tier === "elevated" || tier === "high")) {
//     addLogEntry({
//       tabId: state.tabId,
//       hostname: state.hostname,
//       type: "score_threshold",
//       detail: `Suspicion score reached ${state.score}/100 (${tier}) on ${state.hostname || "unknown host"}`
//     });
//   }
//   state.lastLoggedTier = tier;
// }

// function freshState(tabId) {
//   return {
//     tabId,
//     hostname: null,
//     url: null,
//     startedAt: Date.now(),
//     requestsByHost: {},        // host -> {count, ips:[], ports:[], types:[]}
//     suspiciousConnections: [], // {host, ip, port, reason}
//     telemetry: {
//       wasmInstantiations: 0,
//       workersCreated: 0,
//       suspiciousWorkerNames: [],
//       websockets: [],
//       longTaskTotalMs: 0,
//       longTaskEvents: 0,
//       memSamples: []
//     },
//     score: 0,
//     vt: { checked: false, malicious: 0, suspicious: 0, lastCheckedAt: null, flaggedIndicators: [] },
//     layer1: emptyLayer1(),     // static JavaScript scan (see layer1.js)
//     layer2: emptyLayer2(),     // dynamic behavior of this page (see layer2.js)
//     lastLoggedTier: "none",
//     lastUpdated: Date.now()
//   };
// }

// function getState(tabId) {
//   if (!tabStates.has(tabId)) tabStates.set(tabId, freshState(tabId));
//   return tabStates.get(tabId);
// }

// function resetState(tabId, url) {
//   const s = freshState(tabId);
//   try { s.hostname = new URL(url).hostname; } catch (e) {}
//   s.url = url;
//   tabStates.set(tabId, s);
//   return s;
// }

// function isSuspiciousHost(host) {
//   const h = (host || "").toLowerCase();
//   return MINING_KEYWORDS.some(k => h.includes(k));
// }

// // ---------- Scoring ----------
// function computeScore(state) {
//   let score = 0;
//   const t = state.telemetry;

//   if (t.wasmInstantiations > 0) score += Math.min(25, 10 + t.wasmInstantiations * 3);
//   if (t.workersCreated > 2) score += 10;
//   if (t.suspiciousWorkerNames.length > 0) score += 30;

//   const suspiciousWs = t.websockets.filter(w => w.suspicious);
//   score += Math.min(30, suspiciousWs.length * 30);

//   if (t.longTaskTotalMs > 6000) score += 25;
//   else if (t.longTaskTotalMs > 3000) score += 15;
//   else if (t.longTaskTotalMs > 1000) score += 5;

//   // Sustained JS heap growth across samples = possible hashing buffers churn
//   const mem = t.memSamples;
//   if (mem.length >= 4) {
//     const first = mem[0].used, last = mem[mem.length - 1].used;
//     const growth = last - first;
//     if (growth > 50 * 1024 * 1024) score += 15; // >50MB net growth while idle-ish
//   }

//   score += Math.min(25, state.suspiciousConnections.length * 12);

//   // VirusTotal — an externally-verified malicious verdict is a strong,
//   // independently-confirmed signal, so it's weighted to push the score into
//   // the "high" tier on its own rather than just nudging it. A suspicious-only
//   // verdict (no malicious votes) is a smaller nudge.
//   if (state.vt) {
//     if (state.vt.malicious > 0) score += 70;
//     else if (state.vt.suspicious > 0) score += 25;
//   }

//   // Layer 1: static scan of the page's scripts. How points are earned is
//   // explained in layer1.js (layer1Points).
//   if (state.layer1) score += state.layer1.points || 0;

//   // Layer 2: dynamic behavior. Only NEW signals add points here (event loop delay,
//   // main-thread load, live workers, WebAssembly memory, process CPU). WASM calls,
//   // long tasks and heap growth are already scored above. See scoreLayer2 in layer2.js.
//   if (state.layer2) score += state.layer2.points || 0;

//   state.score = Math.max(0, Math.min(100, Math.round(score)));
//   return state.score;
// }

// function updateBadge(tabId, state) {
//   const score = state.score;
//   let text = "", color = "#4CAF50";
//   if (score >= 60) { text = "!!"; color = "#D32F2F"; }
//   else if (score >= 30) { text = "!"; color = "#F9A825"; }
//   else if (score > 0) { text = "·"; color = "#4CAF50"; }
//   try {
//     chrome.action.setBadgeText({ tabId, text });
//     chrome.action.setBadgeBackgroundColor({ tabId, color });
//   } catch (e) {}
// }

// // ---------- Network artifact collection ----------
// chrome.webRequest.onCompleted.addListener(
//   (details) => {
//     if (details.tabId < 0) return;
//     const state = getState(details.tabId);
//     let host, port;
//     try {
//       const u = new URL(details.url);
//       host = u.hostname;
//       port = u.port || (u.protocol === "https:" ? 443 : 80);
//     } catch (e) { return; }

//     if (!state.requestsByHost[host]) {
//       state.requestsByHost[host] = { count: 0, ips: [], ports: [], types: [] };
//     }
//     const rec = state.requestsByHost[host];
//     rec.count++;
//     if (details.ip && !rec.ips.includes(details.ip)) rec.ips.push(details.ip);
//     if (!rec.ports.includes(port)) rec.ports.push(port);
//     if (!rec.types.includes(details.type)) rec.types.push(details.type);

//     const portHit = SUSPICIOUS_PORTS.has(Number(port));
//     const kwHit = isSuspiciousHost(host);
//     if ((portHit || kwHit) && !state.suspiciousConnections.some(c => c.host === host && c.port === port)) {
//       const reason = [portHit ? "known miner/stratum port" : null, kwHit ? "hostname matches mining keyword" : null]
//         .filter(Boolean).join(" + ");
//       state.suspiciousConnections.push({ host, ip: details.ip || null, port, reason });
//       addLogEntry({
//         tabId: details.tabId,
//         hostname: state.hostname,
//         type: "suspicious_connection",
//         detail: `${host}:${port} — ${reason}`
//       });
//     }

//     state.lastUpdated = Date.now();
//     computeScore(state);
//     maybeLogScoreTier(state);
//     updateBadge(details.tabId, state);
//   },
//   { urls: ["<all_urls>"] }
// );

// // Reset per-tab stats on each new top-level navigation so numbers reflect
// // the current page rather than accumulating across unrelated sites.
// chrome.webNavigation.onCommitted.addListener((details) => {
//   if (details.frameId !== 0) return;
//   resetState(details.tabId, details.url);
// });

// chrome.tabs.onRemoved.addListener((tabId) => {
//   tabStates.delete(tabId);
// });

// // ---------- Telemetry from content script (page-hook signals) ----------
// chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
//   if (msg.type === "TELEMETRY" && sender.tab) {
//     const state = getState(sender.tab.id);
//     const p = msg.payload;
//     state.telemetry.wasmInstantiations += p.wasmInstantiations || 0;
//     state.telemetry.workersCreated += p.workersCreated || 0;
//     (p.suspiciousWorkerNames || []).forEach(w => {
//       if (!state.telemetry.suspiciousWorkerNames.includes(w)) state.telemetry.suspiciousWorkerNames.push(w);
//     });
//     (p.websockets || []).forEach(ws => {
//       if (!state.telemetry.websockets.some(x => x.url === ws.url)) state.telemetry.websockets.push(ws);
//     });
//     state.telemetry.longTaskTotalMs += p.longTaskTotalMs || 0;
//     state.telemetry.longTaskEvents += p.longTasks || 0;
//     if (p.memorySamples && p.memorySamples.length) {
//       state.telemetry.memSamples.push(...p.memorySamples);
//       if (state.telemetry.memSamples.length > 20) {
//         state.telemetry.memSamples = state.telemetry.memSamples.slice(-20);
//       }
//     }
//     if (p.dynamic) mergeDynamic(state.layer2, p.dynamic); // Layer 2 numbers from page-hook.js
//     refreshLayer2(sender.tab.id, state);
//     state.lastUpdated = Date.now();
//     computeScore(state);
//     maybeLogScoreTier(state);
//     updateBadge(sender.tab.id, state);
//     sendResponse({ ok: true });
//     return true;
//   }

//   // Layer 2: "Measure this tab" button in the popup
//   if (msg.type === "LAYER2_MEASURE_NOW") {
//     measureNow(msg.tabId, msg.seconds).then(sendResponse);
//     return true; // async
//   }

//   // Layer 1: scripts sent by layer1_scan.js after the page loads
//   if (msg.type === "LAYER1_PAGE_DATA" && sender.tab) {
//     handleLayer1Data(sender.tab.id, msg, false).then(() => sendResponse({ ok: true }));
//     return true; // async
//   }

//   // Layer 1: "Scan this page now" button in the popup
//   if (msg.type === "LAYER1_SCAN_NOW") {
//     scanTabNow(msg.tabId).then(sendResponse);
//     return true; // async
//   }

//   if (msg.type === "GET_STATE") {
//     const tabId = msg.tabId;
//     const state = tabStates.get(tabId) || null;
//     sendResponse({ state });
//     return true;
//   }

//   // Broader, cross-tab view for the full dashboard tab: every tab currently
//   // being tracked, not just the active one.
//   if (msg.type === "GET_ALL_STATES") {
//     sendResponse({ states: Array.from(tabStates.values()) });
//     return true;
//   }

//   if (msg.type === "GET_SYSTEM_USAGE") {
//     sendResponse({ usage: systemUsage });
//     return true;
//   }

//   if (msg.type === "GET_EVENT_LOG") {
//     chrome.storage.local.get(EVENT_LOG_KEY).then((store) => {
//       sendResponse({ log: (store[EVENT_LOG_KEY] || []).slice().reverse() });
//     });
//     return true; // async
//   }

//   if (msg.type === "CLEAR_EVENT_LOG") {
//     chrome.storage.local.set({ [EVENT_LOG_KEY]: [] }).then(() => sendResponse({ ok: true }));
//     return true; // async
//   }

//   if (msg.type === "GET_VT_RESULTS") {
//     getAllVtResults().then(results => sendResponse({ results }));
//     return true; // async
//   }

//   if (msg.type === "SCAN_VT") {
//     scanTabWithVirusTotal(msg.tabId).then(sendResponse);
//     return true; // async
//   }
// });

// // ---------- VirusTotal client (signature-based reputation lookups) ----------
// const VT_BASE = "https://www.virustotal.com/api/v3";
// const VT_MIN_INTERVAL_MS = 16000; // public API: 4 req/min, stay under it
// let vtQueueTail = Promise.resolve();

// async function getApiKey() {
//   const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
//   return vtApiKey || "";
// }

// async function vtCacheGet(key) {
//   const store = await chrome.storage.local.get(key);
//   const entry = store[key];
//   if (entry && Date.now() - entry.ts < 60 * 60 * 1000) return entry.data;
//   return null;
// }
// async function vtCacheSet(key, data) {
//   await chrome.storage.local.set({ [key]: { ts: Date.now(), data } });
// }

// function vtQueue(fn) {
//   const run = vtQueueTail.then(async () => {
//     const result = await fn();
//     await new Promise(r => setTimeout(r, VT_MIN_INTERVAL_MS));
//     return result;
//   });
//   vtQueueTail = run.catch(() => {});
//   return run;
// }

// async function vtLookupDomain(domain) {
//   const cacheKey = `vtcache_domain_${domain}`;
//   const cached = await vtCacheGet(cacheKey);
//   if (cached) return cached;

//   const apiKey = await getApiKey();
//   if (!apiKey) return { error: "no_api_key" };

//   return vtQueue(async () => {
//     try {
//       const res = await fetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
//         headers: { "x-apikey": apiKey }
//       });
//       if (res.status === 404) {
//         const result = { indicator: domain, notFound: true };
//         await vtCacheSet(cacheKey, result);
//         return result;
//       }
//       if (!res.ok) return { error: `http_${res.status}` };
//       const json = await res.json();
//       const stats = json?.data?.attributes?.last_analysis_stats || {};
//       const result = { indicator: domain, type: "domain", stats };
//       await vtCacheSet(cacheKey, result);
//       return result;
//     } catch (e) {
//       return { error: String(e) };
//     }
//   });
// }

// async function vtLookupIp(ip) {
//   const cacheKey = `vtcache_ip_${ip}`;
//   const cached = await vtCacheGet(cacheKey);
//   if (cached) return cached;

//   const apiKey = await getApiKey();
//   if (!apiKey) return { error: "no_api_key" };

//   return vtQueue(async () => {
//     try {
//       const res = await fetch(`${VT_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
//         headers: { "x-apikey": apiKey }
//       });
//       if (res.status === 404) {
//         const result = { indicator: ip, notFound: true };
//         await vtCacheSet(cacheKey, result);
//         return result;
//       }
//       if (!res.ok) return { error: `http_${res.status}` };
//       const json = await res.json();
//       const stats = json?.data?.attributes?.last_analysis_stats || {};
//       const result = { indicator: ip, type: "ip", stats };
//       await vtCacheSet(cacheKey, result);
//       return result;
//     } catch (e) {
//       return { error: String(e) };
//     }
//   });
// }

// async function scanTabWithVirusTotal(tabId) {
//   const state = tabStates.get(tabId);
//   if (!state) return { error: "no_state" };

//   const hosts = Object.keys(state.requestsByHost);
//   // Prioritize the page's own host + any host flagged suspicious, cap at 5
//   // total lookups per scan click to respect VT's free-tier rate limit.
//   const suspiciousHosts = state.suspiciousConnections.map(c => c.host);
//   const prioritized = [...new Set([state.hostname, ...suspiciousHosts, ...hosts])].filter(Boolean).slice(0, 5);

//   const ips = new Set();
//   prioritized.forEach(h => (state.requestsByHost[h]?.ips || []).forEach(ip => ips.add(ip)));
//   const ipList = [...ips].slice(0, 3);

//   const domainResults = [];
//   for (const h of prioritized) {
//     domainResults.push(await vtLookupDomain(h));
//   }
//   const ipResults = [];
//   for (const ip of ipList) {
//     ipResults.push(await vtLookupIp(ip));
//   }

//   const allResults = [...domainResults, ...ipResults];
//   const maliciousHits = allResults.filter(r => r?.stats && (r.stats.malicious || 0) > 0);
//   const suspiciousOnlyHits = allResults.filter(r => r?.stats && (r.stats.malicious || 0) === 0 && (r.stats.suspicious || 0) > 0);

//   state.vt = {
//     checked: true,
//     lastCheckedAt: Date.now(),
//     malicious: maliciousHits.length,
//     suspicious: suspiciousOnlyHits.length,
//     flaggedIndicators: [...maliciousHits, ...suspiciousOnlyHits].map(r => r.indicator)
//   };
//   computeScore(state);
//   maybeLogScoreTier(state);
//   updateBadge(tabId, state);

//   let severity = "clean";
//   let detail;
//   if (maliciousHits.length) {
//     severity = "critical";
//     detail = `VirusTotal flagged ${maliciousHits.length} indicator(s) as MALICIOUS: ${maliciousHits.map(f => f.indicator).join(", ")}`;
//   } else if (suspiciousOnlyHits.length) {
//     severity = "elevated";
//     detail = `VirusTotal flagged ${suspiciousOnlyHits.length} indicator(s) as suspicious: ${suspiciousOnlyHits.map(f => f.indicator).join(", ")}`;
//   } else {
//     detail = `VirusTotal scan completed — no malicious/suspicious indicators among ${allResults.length} checked`;
//   }

//   addLogEntry({
//     tabId,
//     hostname: state.hostname,
//     type: "vt_scan",
//     severity,
//     detail
//   });

//   return { domainResults, ipResults };
// }

// // All checked domains/IPs live in the shared 1hr cache (vtcache_domain_*,
// // vtcache_ip_*) regardless of which tab triggered the lookup, so the
// // dashboard can show a full, cross-tab VirusTotal results table just by
// // reading that cache back — no extra API calls, no extra storage needed.
// async function getAllVtResults() {
//   try {
//     const all = await chrome.storage.local.get(null);
//     const results = [];
//     for (const [key, val] of Object.entries(all)) {
//       if ((key.startsWith("vtcache_domain_") || key.startsWith("vtcache_ip_")) && val && val.data) {
//         results.push({ ...val.data, checkedAt: val.ts });
//       }
//     }
//     results.sort((a, b) => {
//       const am = a.stats?.malicious || 0, bm = b.stats?.malicious || 0;
//       if (bm !== am) return bm - am;
//       const as = a.stats?.suspicious || 0, bs = b.stats?.suspicious || 0;
//       if (bs !== as) return bs - as;
//       return (a.indicator || "").localeCompare(b.indicator || "");
//     });
//     return results;
//   } catch (e) {
//     return [];
//   }
// }

// // ---------- Layer 1: static JavaScript scanner ----------
// // The page sends us the text of its inline <script> tags and the addresses of
// // its external script files (layer1_scan.js).
// //   Step 1, always (tiny): scan the inline code and the file addresses.
// //   Step 2, only when the machine is busy or the user presses "Scan this page
// //           now": download the external script files and scan their text too.
// // That keeps the layer light, as the supervisor asked: cheap checks first,
// // heavier ones only when something looks busy.

// function hostOfUrl(url) {
//   try { return new URL(url).hostname; } catch (e) { return ""; }
// }

// async function ensureTabIdentity(state, tabId) {
//   if (state.hostname) return;
//   try {
//     const tab = await chrome.tabs.get(tabId);
//     state.hostname = hostOfUrl(tab.url);
//     state.url = tab.url;
//   } catch (e) {}
// }

// // Downloads at most maxBytes of a script file. Cookies are not sent, and the
// // browser cache is preferred (the page already downloaded this file).
// async function fetchTextCapped(url, maxBytes, timeoutMs) {
//   const ctrl = new AbortController();
//   const timer = setTimeout(() => ctrl.abort(), timeoutMs);
//   try {
//     const res = await fetch(url, { signal: ctrl.signal, credentials: "omit", cache: "force-cache" });
//     if (!res.ok || !res.body) return null;
//     const reader = res.body.getReader();
//     const decoder = new TextDecoder("utf-8", { fatal: false });
//     let received = 0;
//     let text = "";
//     while (received < maxBytes) {
//       const { done, value } = await reader.read();
//       if (done) break;
//       received += value.length;
//       text += decoder.decode(value, { stream: true });
//     }
//     ctrl.abort(); // stop downloading the rest
//     return text;
//   } catch (e) {
//     return null;
//   } finally {
//     clearTimeout(timer);
//   }
// }

// async function runDeepScan(state, signatures) {
//   const l1 = state.layer1;
//   const pageHost = state.hostname || "";
//   const room = LAYER1_LIMITS.maxExternalPerPage - (l1.externalDone + l1.externalFailed);
//   if (room <= 0 || !l1.externalQueue.length) return;

//   // Third-party scripts first: that is where miners usually come from.
//   const batch = l1.externalQueue
//     .slice()
//     .sort((a, b) => Number(isThirdParty(b, pageHost)) - Number(isThirdParty(a, pageHost)))
//     .slice(0, Math.min(LAYER1_LIMITS.maxExternalFiles, room));
//   l1.externalQueue = l1.externalQueue.filter((u) => !batch.includes(u));

//   for (let i = 0; i < batch.length; i += 4) {
//     const chunk = batch.slice(i, i + 4);
//     const texts = await Promise.all(
//       chunk.map((u) => fetchTextCapped(u, LAYER1_LIMITS.maxExternalBytes, LAYER1_LIMITS.fetchTimeoutMs))
//     );
//     const sources = [];
//     texts.forEach((text, j) => {
//       if (text == null) l1.externalFailed++;
//       else {
//         l1.externalDone++;
//         sources.push({ label: chunk[j], kind: "external", text });
//       }
//     });
//     mergeHitMaps(l1.hitMap, scanSources(sources, signatures));
//   }
// }

// function finishLayer1(tabId, state) {
//   const l1 = state.layer1;
//   Object.assign(l1, summarize(l1.hitMap));
//   l1.externalTotal = Object.keys(l1.urlsSeen).length;
//   computeScore(state);

//   if (l1.level !== l1.lastLoggedLevel && (l1.level === "strong" || l1.level === "possible")) {
//     const names = l1.hits.filter((h) => h.weight >= 2).slice(0, 4).map((h) => h.keyword).join(", ");
//     addLogEntry({
//       tabId,
//       hostname: state.hostname,
//       type: "static_scan",
//       severity: "elevated",
//       detail: `Static scan found ${l1.level === "strong" ? "strong" : "possible"} miner signs in page scripts (${names})`
//     });
//   }
//   l1.lastLoggedLevel = l1.level;
//   maybeLogScoreTier(state);
//   updateBadge(tabId, state);
// }

// async function handleLayer1Data(tabId, msg, manual) {
//   const state = getState(tabId);
//   await ensureTabIdentity(state, tabId);
//   const settings = await loadSettings();

//   if (!settings.layer1Enabled) {
//     state.layer1 = Object.assign(emptyLayer1(), { disabled: true });
//     computeScore(state);
//     updateBadge(tabId, state);
//     return state.layer1;
//   }
//   if (!state.layer1 || state.layer1.disabled) state.layer1 = emptyLayer1();
//   const l1 = state.layer1;
//   const signatures = activeSignatures(SIGNATURES, settings);

//   const sources = [];
//   (msg.inline || []).forEach((text) => {
//     l1.inlineScanned++;
//     sources.push({ label: `inline script ${l1.inlineScanned}`, kind: "inline", text });
//   });
//   (msg.urls || []).forEach((url) => {
//     sources.push({ label: url, kind: "url", text: url }); // file names count too
//     if (isFetchableUrl(url) && !l1.urlsSeen[url] && Object.keys(l1.urlsSeen).length < LAYER1_LIMITS.maxUrlsTracked) {
//       l1.urlsSeen[url] = 1;
//       l1.externalQueue.push(url);
//     }
//   });
//   mergeHitMaps(l1.hitMap, scanSources(sources, signatures));
//   l1.scannedAt = Date.now();

//   const cpu = systemUsage.cpuPercent;
//   const busy = settings.deepScanCpu === 0 || (cpu != null && cpu >= settings.deepScanCpu);
//   if (settings.fetchExternal && (manual || busy)) {
//     await runDeepScan(state, signatures);
//   }
//   finishLayer1(tabId, state);
//   return l1;
// }

// // Popup button: ask the page for a fresh read, then scan everything,
// // including external files, whatever the CPU is doing.
// async function scanTabNow(tabId) {
//   try {
//     const data = await chrome.tabs.sendMessage(tabId, { type: "LAYER1_COLLECT" });
//     const state = getState(tabId);
//     state.layer1 = emptyLayer1();
//     await handleLayer1Data(tabId, { inline: data.inline, urls: data.urls }, true);
//     return { ok: true, layer1: state.layer1 };
//   } catch (e) {
//     return { ok: false, error: "no_content_script" };
//   }
// }

// // When the periodic CPU check finds the machine busy, read the external
// // scripts of the tab the user is looking at (if they were skipped earlier).
// async function maybeDeepScanActiveTab(settings, cpu) {
//   if (!settings.layer1Enabled || !settings.fetchExternal) return;
//   if (!(settings.deepScanCpu === 0 || cpu >= settings.deepScanCpu)) return;
//   const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
//   const state = tab && tabStates.get(tab.id);
//   if (!state || !state.layer1 || !state.layer1.externalQueue.length) return;
//   await runDeepScan(state, activeSignatures(SIGNATURES, settings));
//   finishLayer1(tab.id, state);
// }

// // ---------- Layer 2: dynamic behavior analysis ----------
// // Two kinds of numbers about ONE tab:
// //   inside the page  (page-hook.js): event loop delay, main-thread load, frames, heap,
// //                    WebAssembly memory, live workers, GPU contexts. Always on, tiny.
// //   outside the page (this file): the tab's renderer process, read with the debugger
// //                    (Performance.getMetrics). Opt-in, short bursts only, because Chrome
// //                    shows a "debugging this browser" bar while the debugger is attached.
// // If chrome.processes exists (Chrome Dev channel + "processes" permission) it is used first.
// // Chrome gives extensions no thread count and no GPU percent; see README.

// const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// const measuring = new Set();

// function refreshLayer2(tabId, state) {
//   const l2 = state.layer2;
//   Object.assign(l2, scoreLayer2(l2));
//   if (l2.level !== l2.lastLoggedLevel && l2.level === "heavy") {
//     addLogEntry({
//       tabId,
//       hostname: state.hostname,
//       type: "dynamic_behavior",
//       severity: "elevated",
//       detail: `Heavy dynamic behavior: ${l2.reasons.slice(0, 3).join("; ")}`
//     });
//   }
//   l2.lastLoggedLevel = l2.level;
// }

// async function readNativeProcessInfo(tabId) {
//   if (!chrome.processes) return null;
//   try {
//     const pid = await new Promise((resolve, reject) =>
//       chrome.processes.getProcessIdForTab(tabId, (id) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(id))));
//     const all = await new Promise((resolve, reject) =>
//       chrome.processes.getProcessInfo(pid, true, (p) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(p))));
//     return all[pid] || Object.values(all)[0] || null;
//   } catch (e) {
//     return null;
//   }
// }

// // Attach the debugger for a few seconds and read the tab's process counters.
// async function readDebuggerSeries(tabId, seconds) {
//   if (!chrome.debugger) throw new Error("no_permission");
//   const target = { tabId };
//   let attached = false;
//   try {
//     await chrome.debugger.attach(target, "1.3");
//     attached = true;
//     await chrome.debugger.sendCommand(target, "Performance.enable");
//     const series = [];
//     const steps = 4;
//     for (let i = 0; i <= steps; i++) {
//       const res = await chrome.debugger.sendCommand(target, "Performance.getMetrics");
//       series.push(metricsToMap(res && res.metrics));
//       if (i === 0) console.log("[JackTrap] Performance.getMetrics names:", Object.keys(series[0]).join(", "));
//       if (i < steps) await delay((seconds * 1000) / steps);
//     }
//     return series;
//   } finally {
//     if (attached) {
//       try { await chrome.debugger.sendCommand(target, "Performance.disable"); } catch (e) {}
//       try { await chrome.debugger.detach(target); } catch (e) {}
//     }
//   }
// }

// async function measureNow(tabId, seconds) {
//   const length = Math.min(15, Math.max(4, Number(seconds) || 8));
//   if (tabId == null) return { ok: false, error: "no_tab" };
//   if (measuring.has(tabId)) return { ok: false, error: "busy" };
//   measuring.add(tabId);
//   try {
//     const state = getState(tabId);
//     await ensureTabIdentity(state, tabId);
//     const cores = self.navigator.hardwareConcurrency || state.layer2.cores || null;

//     let proc = processFromNative(await readNativeProcessInfo(tabId), cores);
//     if (!proc) {
//       const series = await readDebuggerSeries(tabId, length);
//       proc = processFromSeries(series, cores);
//       if (!proc) return { ok: false, error: "no_metrics" };
//     }
//     state.layer2.process = proc;
//     if (cores) state.layer2.cores = cores;
//     refreshLayer2(tabId, state);
//     computeScore(state);
//     maybeLogScoreTier(state);
//     updateBadge(tabId, state);
//     return { ok: true, process: proc };
//   } catch (e) {
//     const text = String((e && e.message) || e);
//     return { ok: false, error: text === "no_permission" ? "no_permission" : "attach_failed", detail: text };
//   } finally {
//     measuring.delete(tabId);
//   }
// }

// // Called by the periodic check: if the machine is busy and precise mode is on,
// // measure the tab the user is looking at (one short burst, never all tabs).
// async function maybeMeasureActiveTab(settings, cpu) {
//   if (!settings.layer2Precise || !chrome.debugger) return;
//   if (!(settings.deepScanCpu === 0 || cpu >= settings.deepScanCpu)) return;
//   const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
//   if (!tab || !tab.id || !/^https?:/.test(tab.url || "")) return;
//   await measureNow(tab.id, 8);
// }

// // ---------- System-wide CPU & memory (chrome.system.cpu / chrome.system.memory) ----------
// // These work on any normal install of Chrome (stable channel, no flags).
// // They are whole-machine numbers, not per-tab. Per-tab numbers come from
// // Layer 2 above: the debugger (opt-in) or chrome.processes (Dev channel only,
// // per Chrome's documentation). Use the whole-machine value as a hint: does a
// // spike here line up with one tab's workers, event loop delay or process CPU?
// let systemUsage = { cpuPercent: null, memUsedBytes: null, memTotalBytes: null, ts: null };
// const SYSTEM_CPU_LOG_THRESHOLD = 85; // percent
// let systemCpuWasHigh = false;
// const SAMPLE_ALARM = "jacktrap_system_sample";

// async function snapshotCpu() {
//   const info = await chrome.system.cpu.getInfo();
//   return info.processors.map((p) => ({ idle: p.usage.idle, total: p.usage.total }));
// }

// // Two snapshots one second apart. Taking both inside one call means the
// // reading still works after the service worker went to sleep between checks.
// async function readSystemCpuPercent() {
//   const a = await snapshotCpu();
//   await new Promise((r) => setTimeout(r, 1000));
//   const b = await snapshotCpu();
//   let used = 0, total = 0;
//   b.forEach((p, i) => {
//     const dTotal = p.total - a[i].total;
//     const dIdle = p.idle - a[i].idle;
//     if (dTotal > 0) { used += dTotal - dIdle; total += dTotal; }
//   });
//   return total > 0 ? Math.round((used / total) * 100) : null;
// }

// async function sampleSystem() {
//   try {
//     if (chrome.system?.cpu) systemUsage.cpuPercent = await readSystemCpuPercent();
//     if (chrome.system?.memory) {
//       const memInfo = await chrome.system.memory.getInfo();
//       systemUsage.memTotalBytes = memInfo.capacity;
//       systemUsage.memUsedBytes = memInfo.capacity - memInfo.availableCapacity;
//     }
//     systemUsage.ts = Date.now();

//     if (systemUsage.cpuPercent != null) {
//       const high = systemUsage.cpuPercent >= SYSTEM_CPU_LOG_THRESHOLD;
//       if (high && !systemCpuWasHigh) {
//         // Best-effort correlation only: name whichever tracked tab currently
//         // scores highest, since there's no way to attribute system CPU to a
//         // specific tab from an extension. Not a claim that tab caused it.
//         const top = [...tabStates.values()].sort((a, b) => (b.score || 0) - (a.score || 0))[0];
//         const hint = top && top.score > 0
//           ? ` Highest-scoring tracked tab right now: ${top.hostname || "unknown"} (score ${top.score}) — worth a look, not a confirmed cause.`
//           : " No tracked tab currently shows elevated behavior signals.";
//         addLogEntry({
//           tabId: top?.tabId ?? null,
//           hostname: top?.hostname ?? null,
//           type: "system_cpu_high",
//           detail: `System-wide CPU usage hit ${systemUsage.cpuPercent}%.${hint}`
//         });
//       }
//       systemCpuWasHigh = high;

//       // Layer 1, step 2: the machine is busy, so read external scripts too.
//       const settings = await loadSettings();
//       await maybeDeepScanActiveTab(settings, systemUsage.cpuPercent);
//       // Layer 2, outside view: measure the active tab's process in one short burst.
//       await maybeMeasureActiveTab(settings, systemUsage.cpuPercent);
//     }
//   } catch (e) {
//     // system.cpu / system.memory can be missing on some platforms; fail quiet
//   }
// }

// // Create the alarm only when it is missing or its period changed. (Calling
// // create() on every worker start would keep resetting the timer.)
// async function applySampleAlarm() {
//   const { sampleMinutes } = await loadSettings();
//   const existing = await chrome.alarms.get(SAMPLE_ALARM);
//   if (!existing || existing.periodInMinutes !== sampleMinutes) {
//     await chrome.alarms.create(SAMPLE_ALARM, { periodInMinutes: sampleMinutes });
//   }
// }

// chrome.alarms.onAlarm.addListener((alarm) => {
//   if (alarm.name === SAMPLE_ALARM) sampleSystem();
// });

// chrome.storage.onChanged.addListener((changes, area) => {
//   if (area !== "local" || !changes[SETTINGS_KEY]) return;
//   const before = (changes[SETTINGS_KEY].oldValue || {}).sampleMinutes;
//   const after = (changes[SETTINGS_KEY].newValue || {}).sampleMinutes;
//   if (before !== after) applySampleAlarm();
// });

// chrome.runtime.onInstalled.addListener(() => {
//   // The VirusTotal key is set on the settings page. It is never stored in code.
//   applySampleAlarm();
// });

// applySampleAlarm();
// sampleSystem(); // seed a first reading on worker startup
