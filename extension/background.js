// ===== JackTrap — background service worker =====
// NOTE (important limitation): a browser extension has NO API to enumerate
// OS-level processes, per-process CPU/RAM, or hash a running executable.
// Everything here is derived from what the browser itself can observe:
// network requests per tab, and in-page JS behavior signals relayed from
// page-hook.js (WASM use, Worker/WebSocket creation, long-task blocking,
// JS heap growth). That's the ceiling of what's possible without a native
// helper app talking to the OS.

const SUSPICIOUS_PORTS = new Set([
  3333, 3357, 4444, 4028, 5555, 5730, 7777, 8080, 8118, 8888,
  9999, 14444, 14433, 45560, 45700
]);
const MINING_KEYWORDS = [
  "xmr", "monero", "stratum", "cryptonight", "nanopool", "minexmr",
  "supportxmr", "webmine", "coinimp", "crypto-loot", "cryptoloot",
  "authedmine", "coinhive", "minero", "jsecoin", "webminepool", "hashvault"
];

const tabStates = new Map(); // tabId -> state

// ---------- Persistent event log (backs the full-dashboard tab) ----------
// tabStates is in-memory only and resets on navigation/SW restart, so
// anything worth reviewing later (a suspicious connection, a score jumping
// into "elevated"/"high", a VT scan result) also gets written here, to
// chrome.storage.local, capped at EVENT_LOG_MAX entries.
const EVENT_LOG_KEY = "jacktrap_eventLog";
const EVENT_LOG_MAX = 300;

// Serialized so concurrent callers (e.g. a suspicious_connection firing at
// the same moment a vt_scan finishes) can't race: read-modify-write on the
// same storage key from two calls at once would let the second overwrite
// the first, silently dropping an entry.
let logWriteTail = Promise.resolve();
function addLogEntry(entry) {
  const run = logWriteTail.then(async () => {
    try {
      const store = await chrome.storage.local.get(EVENT_LOG_KEY);
      const log = store[EVENT_LOG_KEY] || [];
      log.push({ ts: Date.now(), ...entry });
      if (log.length > EVENT_LOG_MAX) log.splice(0, log.length - EVENT_LOG_MAX);
      await chrome.storage.local.set({ [EVENT_LOG_KEY]: log });
    } catch (e) {}
  });
  logWriteTail = run.catch(() => {});
  return run;
}

function scoreTier(score) {
  if (score >= 60) return "high";
  if (score >= 30) return "elevated";
  if (score > 0) return "low";
  return "none";
}

// Logs a score-threshold crossing at most once per tier, per navigation.
function maybeLogScoreTier(state) {
  const tier = scoreTier(state.score);
  if (tier !== state.lastLoggedTier && (tier === "elevated" || tier === "high")) {
    addLogEntry({
      tabId: state.tabId,
      hostname: state.hostname,
      type: "score_threshold",
      detail: `Suspicion score reached ${state.score}/100 (${tier}) on ${state.hostname || "unknown host"}`
    });
  }
  state.lastLoggedTier = tier;
}

function freshState(tabId) {
  return {
    tabId,
    hostname: null,
    url: null,
    startedAt: Date.now(),
    requestsByHost: {},        // host -> {count, ips:[], ports:[], types:[]}
    suspiciousConnections: [], // {host, ip, port, reason}
    telemetry: {
      wasmInstantiations: 0,
      workersCreated: 0,
      suspiciousWorkerNames: [],
      websockets: [],
      longTaskTotalMs: 0,
      longTaskEvents: 0,
      memSamples: []
    },
    score: 0,
    vt: { checked: false, malicious: 0, suspicious: 0, lastCheckedAt: null, flaggedIndicators: [] },
    lastLoggedTier: "none",
    lastUpdated: Date.now()
  };
}

function getState(tabId) {
  if (!tabStates.has(tabId)) tabStates.set(tabId, freshState(tabId));
  return tabStates.get(tabId);
}

function resetState(tabId, url) {
  const s = freshState(tabId);
  try { s.hostname = new URL(url).hostname; } catch (e) {}
  s.url = url;
  tabStates.set(tabId, s);
  return s;
}

function isSuspiciousHost(host) {
  const h = (host || "").toLowerCase();
  return MINING_KEYWORDS.some(k => h.includes(k));
}

// ---------- Scoring ----------
function computeScore(state) {
  let score = 0;
  const t = state.telemetry;

  if (t.wasmInstantiations > 0) score += Math.min(25, 10 + t.wasmInstantiations * 3);
  if (t.workersCreated > 2) score += 10;
  if (t.suspiciousWorkerNames.length > 0) score += 30;

  const suspiciousWs = t.websockets.filter(w => w.suspicious);
  score += Math.min(30, suspiciousWs.length * 30);

  if (t.longTaskTotalMs > 6000) score += 25;
  else if (t.longTaskTotalMs > 3000) score += 15;
  else if (t.longTaskTotalMs > 1000) score += 5;

  // Sustained JS heap growth across samples = possible hashing buffers churn
  const mem = t.memSamples;
  if (mem.length >= 4) {
    const first = mem[0].used, last = mem[mem.length - 1].used;
    const growth = last - first;
    if (growth > 50 * 1024 * 1024) score += 15; // >50MB net growth while idle-ish
  }

  score += Math.min(25, state.suspiciousConnections.length * 12);

  // VirusTotal — an externally-verified malicious verdict is a strong,
  // independently-confirmed signal, so it's weighted to push the score into
  // the "high" tier on its own rather than just nudging it. A suspicious-only
  // verdict (no malicious votes) is a smaller nudge.
  if (state.vt) {
    if (state.vt.malicious > 0) score += 70;
    else if (state.vt.suspicious > 0) score += 25;
  }

  state.score = Math.max(0, Math.min(100, Math.round(score)));
  return state.score;
}

function updateBadge(tabId, state) {
  const score = state.score;
  let text = "", color = "#4CAF50";
  if (score >= 60) { text = "!!"; color = "#D32F2F"; }
  else if (score >= 30) { text = "!"; color = "#F9A825"; }
  else if (score > 0) { text = "·"; color = "#4CAF50"; }
  try {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (e) {}
}

// ---------- Network artifact collection ----------
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const state = getState(details.tabId);
    let host, port;
    try {
      const u = new URL(details.url);
      host = u.hostname;
      port = u.port || (u.protocol === "https:" ? 443 : 80);
    } catch (e) { return; }

    if (!state.requestsByHost[host]) {
      state.requestsByHost[host] = { count: 0, ips: [], ports: [], types: [] };
    }
    const rec = state.requestsByHost[host];
    rec.count++;
    if (details.ip && !rec.ips.includes(details.ip)) rec.ips.push(details.ip);
    if (!rec.ports.includes(port)) rec.ports.push(port);
    if (!rec.types.includes(details.type)) rec.types.push(details.type);

    const portHit = SUSPICIOUS_PORTS.has(Number(port));
    const kwHit = isSuspiciousHost(host);
    if ((portHit || kwHit) && !state.suspiciousConnections.some(c => c.host === host && c.port === port)) {
      const reason = [portHit ? "known miner/stratum port" : null, kwHit ? "hostname matches mining keyword" : null]
        .filter(Boolean).join(" + ");
      state.suspiciousConnections.push({ host, ip: details.ip || null, port, reason });
      addLogEntry({
        tabId: details.tabId,
        hostname: state.hostname,
        type: "suspicious_connection",
        detail: `${host}:${port} — ${reason}`
      });
    }

    state.lastUpdated = Date.now();
    computeScore(state);
    maybeLogScoreTier(state);
    updateBadge(details.tabId, state);
  },
  { urls: ["<all_urls>"] }
);

// Reset per-tab stats on each new top-level navigation so numbers reflect
// the current page rather than accumulating across unrelated sites.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  resetState(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

// ---------- Telemetry from content script (page-hook signals) ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "TELEMETRY" && sender.tab) {
    const state = getState(sender.tab.id);
    const p = msg.payload;
    state.telemetry.wasmInstantiations += p.wasmInstantiations || 0;
    state.telemetry.workersCreated += p.workersCreated || 0;
    (p.suspiciousWorkerNames || []).forEach(w => {
      if (!state.telemetry.suspiciousWorkerNames.includes(w)) state.telemetry.suspiciousWorkerNames.push(w);
    });
    (p.websockets || []).forEach(ws => {
      if (!state.telemetry.websockets.some(x => x.url === ws.url)) state.telemetry.websockets.push(ws);
    });
    state.telemetry.longTaskTotalMs += p.longTaskTotalMs || 0;
    state.telemetry.longTaskEvents += p.longTasks || 0;
    if (p.memorySamples && p.memorySamples.length) {
      state.telemetry.memSamples.push(...p.memorySamples);
      if (state.telemetry.memSamples.length > 20) {
        state.telemetry.memSamples = state.telemetry.memSamples.slice(-20);
      }
    }
    state.lastUpdated = Date.now();
    computeScore(state);
    maybeLogScoreTier(state);
    updateBadge(sender.tab.id, state);
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "GET_STATE") {
    const tabId = msg.tabId;
    const state = tabStates.get(tabId) || null;
    sendResponse({ state });
    return true;
  }

  // Broader, cross-tab view for the full dashboard tab: every tab currently
  // being tracked, not just the active one.
  if (msg.type === "GET_ALL_STATES") {
    sendResponse({ states: Array.from(tabStates.values()) });
    return true;
  }

  if (msg.type === "GET_SYSTEM_USAGE") {
    sendResponse({ usage: systemUsage });
    return true;
  }

  if (msg.type === "GET_EVENT_LOG") {
    chrome.storage.local.get(EVENT_LOG_KEY).then((store) => {
      sendResponse({ log: (store[EVENT_LOG_KEY] || []).slice().reverse() });
    });
    return true; // async
  }

  if (msg.type === "CLEAR_EVENT_LOG") {
    chrome.storage.local.set({ [EVENT_LOG_KEY]: [] }).then(() => sendResponse({ ok: true }));
    return true; // async
  }

  if (msg.type === "GET_VT_RESULTS") {
    getAllVtResults().then(results => sendResponse({ results }));
    return true; // async
  }

  if (msg.type === "SCAN_VT") {
    scanTabWithVirusTotal(msg.tabId).then(sendResponse);
    return true; // async
  }
});

// ---------- VirusTotal client (signature-based reputation lookups) ----------
const VT_BASE = "https://www.virustotal.com/api/v3";
const VT_MIN_INTERVAL_MS = 16000; // public API: 4 req/min, stay under it
let vtQueueTail = Promise.resolve();

async function getApiKey() {
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  return vtApiKey || "";
}

async function vtCacheGet(key) {
  const store = await chrome.storage.local.get(key);
  const entry = store[key];
  if (entry && Date.now() - entry.ts < 60 * 60 * 1000) return entry.data;
  return null;
}
async function vtCacheSet(key, data) {
  await chrome.storage.local.set({ [key]: { ts: Date.now(), data } });
}

function vtQueue(fn) {
  const run = vtQueueTail.then(async () => {
    const result = await fn();
    await new Promise(r => setTimeout(r, VT_MIN_INTERVAL_MS));
    return result;
  });
  vtQueueTail = run.catch(() => {});
  return run;
}

async function vtLookupDomain(domain) {
  const cacheKey = `vtcache_domain_${domain}`;
  const cached = await vtCacheGet(cacheKey);
  if (cached) return cached;

  const apiKey = await getApiKey();
  if (!apiKey) return { error: "no_api_key" };

  return vtQueue(async () => {
    try {
      const res = await fetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
        headers: { "x-apikey": apiKey }
      });
      if (res.status === 404) {
        const result = { indicator: domain, notFound: true };
        await vtCacheSet(cacheKey, result);
        return result;
      }
      if (!res.ok) return { error: `http_${res.status}` };
      const json = await res.json();
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const result = { indicator: domain, type: "domain", stats };
      await vtCacheSet(cacheKey, result);
      return result;
    } catch (e) {
      return { error: String(e) };
    }
  });
}

async function vtLookupIp(ip) {
  const cacheKey = `vtcache_ip_${ip}`;
  const cached = await vtCacheGet(cacheKey);
  if (cached) return cached;

  const apiKey = await getApiKey();
  if (!apiKey) return { error: "no_api_key" };

  return vtQueue(async () => {
    try {
      const res = await fetch(`${VT_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
        headers: { "x-apikey": apiKey }
      });
      if (res.status === 404) {
        const result = { indicator: ip, notFound: true };
        await vtCacheSet(cacheKey, result);
        return result;
      }
      if (!res.ok) return { error: `http_${res.status}` };
      const json = await res.json();
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const result = { indicator: ip, type: "ip", stats };
      await vtCacheSet(cacheKey, result);
      return result;
    } catch (e) {
      return { error: String(e) };
    }
  });
}

async function scanTabWithVirusTotal(tabId) {
  const state = tabStates.get(tabId);
  if (!state) return { error: "no_state" };

  const hosts = Object.keys(state.requestsByHost);
  // Prioritize the page's own host + any host flagged suspicious, cap at 5
  // total lookups per scan click to respect VT's free-tier rate limit.
  const suspiciousHosts = state.suspiciousConnections.map(c => c.host);
  const prioritized = [...new Set([state.hostname, ...suspiciousHosts, ...hosts])].filter(Boolean).slice(0, 5);

  const ips = new Set();
  prioritized.forEach(h => (state.requestsByHost[h]?.ips || []).forEach(ip => ips.add(ip)));
  const ipList = [...ips].slice(0, 3);

  const domainResults = [];
  for (const h of prioritized) {
    domainResults.push(await vtLookupDomain(h));
  }
  const ipResults = [];
  for (const ip of ipList) {
    ipResults.push(await vtLookupIp(ip));
  }

  const allResults = [...domainResults, ...ipResults];
  const maliciousHits = allResults.filter(r => r?.stats && (r.stats.malicious || 0) > 0);
  const suspiciousOnlyHits = allResults.filter(r => r?.stats && (r.stats.malicious || 0) === 0 && (r.stats.suspicious || 0) > 0);

  state.vt = {
    checked: true,
    lastCheckedAt: Date.now(),
    malicious: maliciousHits.length,
    suspicious: suspiciousOnlyHits.length,
    flaggedIndicators: [...maliciousHits, ...suspiciousOnlyHits].map(r => r.indicator)
  };
  computeScore(state);
  maybeLogScoreTier(state);
  updateBadge(tabId, state);

  let severity = "clean";
  let detail;
  if (maliciousHits.length) {
    severity = "critical";
    detail = `VirusTotal flagged ${maliciousHits.length} indicator(s) as MALICIOUS: ${maliciousHits.map(f => f.indicator).join(", ")}`;
  } else if (suspiciousOnlyHits.length) {
    severity = "elevated";
    detail = `VirusTotal flagged ${suspiciousOnlyHits.length} indicator(s) as suspicious: ${suspiciousOnlyHits.map(f => f.indicator).join(", ")}`;
  } else {
    detail = `VirusTotal scan completed — no malicious/suspicious indicators among ${allResults.length} checked`;
  }

  addLogEntry({
    tabId,
    hostname: state.hostname,
    type: "vt_scan",
    severity,
    detail
  });

  return { domainResults, ipResults };
}

// All checked domains/IPs live in the shared 1hr cache (vtcache_domain_*,
// vtcache_ip_*) regardless of which tab triggered the lookup, so the
// dashboard can show a full, cross-tab VirusTotal results table just by
// reading that cache back — no extra API calls, no extra storage needed.
async function getAllVtResults() {
  try {
    const all = await chrome.storage.local.get(null);
    const results = [];
    for (const [key, val] of Object.entries(all)) {
      if ((key.startsWith("vtcache_domain_") || key.startsWith("vtcache_ip_")) && val && val.data) {
        results.push({ ...val.data, checkedAt: val.ts });
      }
    }
    results.sort((a, b) => {
      const am = a.stats?.malicious || 0, bm = b.stats?.malicious || 0;
      if (bm !== am) return bm - am;
      const as = a.stats?.suspicious || 0, bs = b.stats?.suspicious || 0;
      if (bs !== as) return bs - as;
      return (a.indicator || "").localeCompare(b.indicator || "");
    });
    return results;
  } catch (e) {
    return [];
  }
}

// ---------- System-wide CPU & memory (chrome.system.cpu / chrome.system.memory) ----------
// These work on any normal install of Chrome (stable channel, no flags, no
// Canary needed) — that part isn't restricted. What IS restricted, on every
// channel, is *per-tab / per-process* CPU and RAM: that's chrome.processes,
// and Chrome only grants it to extensions force-installed by enterprise
// policy. A normal "Load unpacked" or Web Store install can't get it,
// regardless of channel. So what's below is whole-machine, not per-tab —
// useful as a correlation signal (does a spike here line up with a spike
// in one tab's WASM/Worker/long-task numbers?), not as attribution on its
// own.
let lastCpuSample = null; // { processors: [{user,kernel,idle,total}] }
let systemUsage = { cpuPercent: null, memUsedBytes: null, memTotalBytes: null, ts: null };
const SYSTEM_CPU_LOG_THRESHOLD = 85; // percent
let systemCpuWasHigh = false;

async function sampleSystem() {
  try {
    if (chrome.system?.cpu) {
      const cpuInfo = await chrome.system.cpu.getInfo();
      const processors = cpuInfo.processors.map(p => ({ ...p.usage }));
      if (lastCpuSample && lastCpuSample.length === processors.length) {
        let usedDelta = 0, totalDelta = 0;
        processors.forEach((p, i) => {
          const prev = lastCpuSample[i];
          const dTotal = p.total - prev.total;
          const dIdle = p.idle - prev.idle;
          if (dTotal > 0) { usedDelta += (dTotal - dIdle); totalDelta += dTotal; }
        });
        systemUsage.cpuPercent = totalDelta > 0 ? Math.round((usedDelta / totalDelta) * 100) : null;
      }
      lastCpuSample = processors;
    }
    if (chrome.system?.memory) {
      const memInfo = await chrome.system.memory.getInfo();
      systemUsage.memTotalBytes = memInfo.capacity;
      systemUsage.memUsedBytes = memInfo.capacity - memInfo.availableCapacity;
    }
    systemUsage.ts = Date.now();

    if (systemUsage.cpuPercent != null) {
      const high = systemUsage.cpuPercent >= SYSTEM_CPU_LOG_THRESHOLD;
      if (high && !systemCpuWasHigh) {
        // Best-effort correlation only: name whichever tracked tab currently
        // scores highest, since there's no way to attribute system CPU to a
        // specific tab from an extension. Not a claim that tab caused it.
        const top = [...tabStates.values()].sort((a, b) => (b.score || 0) - (a.score || 0))[0];
        const hint = top && top.score > 0
          ? ` Highest-scoring tracked tab right now: ${top.hostname || "unknown"} (score ${top.score}) — worth a look, not a confirmed cause.`
          : " No tracked tab currently shows elevated behavior signals.";
        addLogEntry({
          tabId: top?.tabId ?? null,
          hostname: top?.hostname ?? null,
          type: "system_cpu_high",
          detail: `System-wide CPU usage hit ${systemUsage.cpuPercent}%.${hint}`
        });
      }
      systemCpuWasHigh = high;
    }
  } catch (e) {
    // system.cpu / system.memory can be missing on some platforms; fail quiet
  }
}

chrome.alarms.create("jacktrap_system_sample", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "jacktrap_system_sample") sampleSystem();
});
sampleSystem(); // seed a first reading on worker startup

chrome.runtime.onInstalled.addListener(async () => {
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  if (!vtApiKey) {
    // Pre-filled from setup; user can change it anytime on the options page.
    await chrome.storage.local.set({
      vtApiKey: "9b85d05d7273e0adb407469fa5cee38199bf404518f45299d66b991210f42bf8"
    });
  }
});
