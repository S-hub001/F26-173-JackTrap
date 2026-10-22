// JackTrap popup.
// Everything shown goes through textContent (never innerHTML): script names,
// host names and code snippets come from untrusted websites.

const $ = (id) => document.getElementById(id);

function h(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

// ---------- state ----------
let tabId = null;
let latest = { state: null, cpu: null, memUsed: null, memTotal: null };
let vtRows = [];
let notice = null; // { text, settings }
const busy = { scan: false, vt: false, measure: false };
const open = new Set();
let autoOpened = false;
let lastKey = "";

// ---------- helpers ----------
function tierOf(state) {
  if (!state) return "none";
  const s = state.score || 0;
  return s >= 60 ? "high" : s >= 30 ? "elevated" : "low";
}

const TIER_WORD = { none: "Not scanned", low: "Low risk", elevated: "Worth a look", high: "High risk" };

function fmtGB(n) {
  return n ? (n / (1024 * 1024 * 1024)).toFixed(1) + " GB" : "0 GB";
}

function strengthWord(weight) {
  return weight >= 4 ? "Strong" : weight >= 2 ? "Possible" : "Weak";
}

function shortLabel(label) {
  const text = String(label || "");
  return text.length > 70 ? text.slice(0, 67) + "…" : text;
}

// One plain sentence: the biggest reason behind the score.
function explain(state) {
  if (!state) return "JackTrap has no data for this page yet. Reload it, or open a normal website.";
  const l1 = state.layer1 || {};
  const t = state.telemetry || {};
  const sus = state.suspiciousConnections || [];
  if (state.vt && state.vt.malicious > 0) return "VirusTotal flags a site this page contacts as malicious.";
  if (l1.level === "strong") {
    const names = (l1.hits || []).filter((x) => x.weight >= 4).slice(0, 3).map((x) => x.keyword).join(", ");
    return "The static scan found miner signatures in the page scripts: " + names + ".";
  }
  if (sus.length) return "This page connects to " + sus[0].host + ":" + sus[0].port + ", which looks like a mining pool.";
  if ((t.suspiciousWorkerNames || []).length) return "A background worker has a mining-style name.";
  if ((t.websockets || []).some((w) => w.suspicious)) return "A WebSocket goes to a mining-style address.";
  const l2 = state.layer2 || {};
  if (l2.level === "heavy" && (l2.reasons || []).length) {
    return "Layer 2 sees heavy activity. " + l2.reasons.slice(0, 2).join(". ") + ".";
  }
  if (l1.level === "possible") return "Some scripts mention mining terms. Honest code does too, so check the details.";
  if ((state.score || 0) >= 30) return "Heavy scripting (WebAssembly, workers or long tasks). Normal for some apps.";
  if ((state.score || 0) > 0) return "A little scripting activity, nothing that looks like mining.";
  return "No miner signatures, odd connections or heavy scripting seen.";
}

// ---------- layers ----------
function kv(label, value) {
  return h("div", { class: "kv" }, h("span", null, label), h("span", null, value));
}

function layerCpu() {
  const cpu = latest.cpu;
  let status = "idle", chip = "Reading…", summary = "Waiting for a second reading";
  if (cpu != null) {
    status = cpu >= 90 ? "alert" : cpu >= 30 ? "watch" : "ok";
    chip = cpu >= 90 ? "Very busy" : cpu >= 30 ? "Busy" : "Normal";
    summary = cpu + "% of the whole machine";
  }
  const body = h("div", null,
    kv("CPU now", cpu == null ? "…" : cpu + "%"),
    kv("Memory used", fmtGB(latest.memUsed) + " / " + fmtGB(latest.memTotal)),
    h("p", { class: "muted" }, "Chrome can’t show CPU for a single tab, so this is a machine-wide hint. High CPU alone is not a verdict: video and games use a lot too.")
  );
  return { id: "cpu", title: "Layer 0 · System CPU", status, chip, summary, body };
}

function layerStatic(state) {
  const l1 = state && state.layer1;
  const title = "Layer 1 · Static scan";
  if (l1 && l1.disabled) {
    return { id: "static", title, status: "idle", chip: "Off", summary: "Turned off in settings",
      body: h("p", { class: "muted" }, "Turn the static scanner back on in settings.") };
  }
  if (!l1 || !l1.scannedAt) {
    return { id: "static", title, status: "idle", chip: "Waiting", summary: "Waiting for the page scripts",
      body: h("p", { class: "muted" }, "JackTrap reads a page’s scripts after it finishes loading. If this stays empty, reload the page once.") };
  }

  const pending = (l1.externalQueue || []).length;
  const read = (l1.externalDone || 0) + (l1.externalFailed || 0);
  const names = (l1.hits || []).filter((x) => x.weight >= 2).slice(0, 2).map((x) => x.keyword);
  const more = (l1.hits || []).filter((x) => x.weight >= 2).length - names.length;

  let status = "ok", chip = "Clear", summary = "No miner words in " + (l1.inlineScanned || 0) + " inline scripts";
  if (l1.level === "strong") { status = "alert"; chip = "Strong signs"; }
  else if (l1.level === "possible") { status = "watch"; chip = "Possible signs"; }
  if (names.length) summary = names.join(", ") + (more > 0 ? " +" + more + " more" : "");

  const body = h("div", null,
    kv("Inline scripts read", l1.inlineScanned || 0),
    kv("Script files read", read + " of " + (l1.externalTotal || 0)),
    pending > 0
      ? h("p", { class: "muted" }, pending + " script file" + (pending === 1 ? "" : "s") + " not read yet, because the CPU is calm. Press “Scan this page now” to read them.")
      : null
  );

  const hits = l1.hits || [];
  if (!hits.length) {
    body.append(h("p", { class: "muted" }, "None of the signature words were found."));
  }
  for (const hit of hits) {
    const counted = hit.weight >= 2 || l1.level !== "clean";
    const word = strengthWord(hit.weight);
    const where = (hit.where || []).map((w) => (w.kind === "inline" ? w.label : shortLabel(w.label)));
    body.append(h("div", { class: "hit" + (counted ? "" : " dim") },
      h("div", { class: "hit-head" },
        h("span", { class: "kw" }, hit.keyword),
        h("span", { class: "chip " + (hit.weight >= 4 ? "alert" : hit.weight >= 2 ? "watch" : "idle") },
          counted ? word : word + ", not counted alone")),
      h("div", { class: "hit-where" }, "Found in " + where.join("; ")),
      hit.where && hit.where[0] && hit.where[0].snippet ? h("div", { class: "snippet" }, hit.where[0].snippet) : null
    ));
  }
  body.append(h("p", { class: "muted", style: "margin-top:8px" },
    "Matching words is a hint, not proof. Obfuscated code can hide them."));
  return { id: "static", title, status, chip, summary, body };
}

function fmtMB(n) {
  return n ? (n / (1024 * 1024)).toFixed(1) + " MB" : "0 MB";
}

function section(title) {
  return h("p", { class: "sub-title" }, title);
}

// Layer 2: dynamic behavior. What this one page is doing to the browser.
function layerDynamic(state) {
  const t = (state && state.telemetry) || {};
  const l2 = (state && state.layer2) || {};
  const page = l2.page;
  const proc = l2.process;
  const cores = l2.cores || (page && page.cores) || 0;
  const susW = (t.suspiciousWorkerNames || []).length;
  const susWs = (t.websockets || []).filter((w) => w.suspicious).length;
  const wasm = t.wasmInstantiations || 0;
  const workers = t.workersCreated || 0;
  const longMs = Math.round(t.longTaskTotalMs || 0);

  let status = "ok", chip = "Calm";
  if (!state) { status = "idle"; chip = "No data"; }
  else if (susW || susWs || l2.level === "heavy") { status = "alert"; chip = susW || susWs ? "Suspicious" : "Heavy"; }
  else if (l2.level === "busy" || wasm > 0 || workers > 2 || longMs > 3000) { status = "watch"; chip = "Busy"; }

  const bits = [];
  if (proc && proc.cpuPct != null) bits.push("CPU " + Math.round(proc.cpuPct) + "%");
  if (page && page.visible && page.loopSamples >= 5) bits.push("loop " + Math.round(page.loopLagP95Ms) + " ms");
  if (page) bits.push(page.workersLive + " workers");
  const summary = bits.length ? bits.join(" · ") : "WASM " + wasm + " · workers " + workers + " · blocked " + longMs + " ms";

  const body = h("div", null);

  // 1) measured from outside the page
  body.append(section("This tab’s process (measured from outside)"));
  if (proc) {
    const rows = [
      kv("Process CPU (of one core)", proc.cpuPct == null ? "not reported" : Math.round(proc.cpuPct) + "%"),
      proc.cpuMachinePct != null ? kv("Share of this machine", Math.round(proc.cpuMachinePct) + "%") : null,
      proc.mainThreadPct != null ? kv("Main thread", Math.round(proc.mainThreadPct) + "%") : null,
      proc.otherThreadsPct != null ? kv("Workers and other threads", Math.round(proc.otherThreadsPct) + "%") : null,
      proc.jsHeapUsed != null ? kv("JavaScript memory", fmtMB(proc.jsHeapUsed) + (proc.jsHeapTotal ? " of " + fmtMB(proc.jsHeapTotal) : "")) : null,
      proc.privateMemory != null ? kv("Private memory", fmtMB(proc.privateMemory)) : null,
      proc.nodes != null ? kv("Page elements (DOM nodes)", proc.nodes) : null,
      proc.workers != null ? kv("Workers alive (Chrome’s count)", proc.workers) : null,
      h("p", { class: "muted" }, "Measured over " + (proc.seconds != null ? proc.seconds + " seconds" : "one reading") + " using " + (proc.source === "chrome.processes" ? "chrome.processes" : "the debugger") + "." +
        (proc.missing && proc.missing.length ? " This Chrome did not report: " + proc.missing.join(", ") + "." : "")),
      proc.cpuPct != null && proc.cpuPct > 100 ? h("p", { class: "muted" }, "Over 100% is normal: it means more than one core is busy. Other tabs of the same site can share this process.") : null
    ];
    body.append(...rows.filter(Boolean));
  } else {
    body.append(h("p", { class: "muted" }, "Not measured yet. Press “Measure this tab” (about 8 seconds). It needs the precise-measurement option in settings."));
  }

  // 2) seen from inside the page
  body.append(section("Seen from inside the page"));
  if (page) {
    if (!page.visible) body.append(h("p", { class: "muted" }, "This tab is in the background, so timing is not measured right now."));
    body.append(
      kv("Event loop delay (p95 / worst)", page.loopSamples >= 5 ? Math.round(page.loopLagP95Ms) + " ms / " + Math.round(page.loopLagMaxMs) + " ms" : "…"),
      kv("Main thread blocked", Math.round(page.busyPct) + "%"),
      kv("Frame rate", page.frameSamples ? page.fps + " fps · " + page.slowFrames + " slow" : "…"),
      kv("JavaScript memory", fmtMB(page.heapUsed) + (page.heapLimit ? " of " + fmtMB(page.heapLimit) + " limit" : "")),
      kv("WebAssembly memory", page.wasmMemories ? fmtMB(page.wasmMemoryBytes) + " in " + page.wasmMemories : "none seen"),
      kv("Workers alive (peak)", page.workersLive + " (" + page.workersPeak + ")" + (cores ? " on " + cores + " cores" : "")),
      kv("GPU contexts", "2D " + page.gpu.canvas2d + " · WebGL " + (page.gpu.webgl + page.gpu.webgl2) + " · WebGPU " + (page.gpu.webgpu + page.gpu.adapterRequests))
    );
  } else {
    body.append(h("p", { class: "muted" }, "Waiting for the first reading (about 4 seconds after the page loads)."));
  }

  // 3) what the page did
  body.append(section("What the page did"));
  body.append(
    kv("WebAssembly starts", wasm),
    kv("Workers created", workers),
    kv("Suspicious workers", susW),
    kv("Suspicious WebSockets", susWs),
    kv("Main thread blocked (total)", longMs + " ms")
  );

  if (l2.reasons && l2.reasons.length) {
    body.append(section("Why Layer 2 added +" + (l2.points || 0) + " to the score"));
    l2.reasons.forEach((r) => body.append(h("p", { class: "reason" }, r)));
  }
  body.append(h("p", { class: "muted", style: "margin-top:8px" },
    "Numbers from inside the page can be faked by a hostile page, so the measured ones are more trustworthy. Chrome gives extensions no thread count or GPU percent; live workers and GPU contexts are the closest signals."));

  return { id: "behavior", title: "Layer 2 · Dynamic behavior", status, chip, summary, body };
}

function layerNetwork(state) {
  const hosts = Object.entries((state && state.requestsByHost) || {});
  const sus = (state && state.suspiciousConnections) || [];
  let status = "ok", chip = "Clear";
  if (!state || !hosts.length) { status = "idle"; chip = "No data"; }
  else if (sus.length) { status = "alert"; chip = "Flagged"; }
  const body = h("div", null);
  for (const c of sus) {
    body.append(h("div", { class: "hostrow flagrow" }, h("span", null, c.host + ":" + c.port), h("span", null, c.reason)));
  }
  hosts.sort((a, b) => b[1].count - a[1].count).slice(0, 8).forEach(([host, rec]) => {
    body.append(h("div", { class: "hostrow" }, h("span", null, host), h("span", null, rec.count + " req")));
  });
  if (!hosts.length) body.append(h("p", { class: "muted" }, "No requests captured yet."));
  return { id: "network", title: "Network", status, chip,
    summary: hosts.length + " hosts · " + sus.length + " flagged", body };
}

function layerVt(state) {
  const vt = state && state.vt;
  let status = "idle", chip = "Not checked", summary = "Press “Check with VirusTotal”";
  if (vt && vt.checked) {
    if (vt.malicious > 0) { status = "alert"; chip = "Malicious"; summary = vt.malicious + " indicator(s) flagged"; }
    else if (vt.suspicious > 0) { status = "watch"; chip = "Suspicious"; summary = vt.suspicious + " indicator(s) look odd"; }
    else { status = "ok"; chip = "Clear"; summary = "Nothing flagged"; }
  }
  const body = h("div", null);
  for (const r of vtRows) {
    if (r.notFound) { body.append(h("div", { class: "hostrow" }, h("span", null, r.indicator), h("span", null, "not in VirusTotal"))); continue; }
    const s = r.stats || {};
    const flagged = (s.malicious || 0) > 0 || (s.suspicious || 0) > 0;
    body.append(h("div", { class: "hostrow" + (flagged ? " flagrow" : "") },
      h("span", null, r.indicator),
      h("span", null, (s.malicious || 0) + " malicious · " + (s.suspicious || 0) + " suspicious")));
  }
  if (!vtRows.length) body.append(h("p", { class: "muted" }, "Checks this page’s host and the hosts it connects to. Free keys allow about 4 lookups a minute, so it can take a while."));
  return { id: "vt", title: "VirusTotal", status, chip, summary, body };
}

// ---------- render ----------
function render() {
  const key = JSON.stringify([latest, vtRows, notice, busy, [...open]]);
  if (key === lastKey) return;
  lastKey = key;

  const state = latest.state;
  const tier = tierOf(state);

  $("pageHost").textContent = (state && state.hostname) || "No page data";
  $("verdict").dataset.tier = tier;
  $("verdictWord").textContent = TIER_WORD[tier];
  $("scoreText").textContent = state ? (state.score || 0) + " / 100" : "";
  $("verdictWhy").textContent = explain(state);
  $("marker").style.left = (state ? Math.min(99, Math.max(1, state.score || 0)) : 0) + "%";
  $("marker").style.display = state ? "block" : "none";
  $("zonebar").setAttribute("aria-label", state ? "Suspicion score " + (state.score || 0) + " out of 100" : "Not scanned");

  const box = $("notice");
  box.replaceChildren();
  box.hidden = !notice;
  if (notice) {
    box.append(h("p", null, notice.text));
    if (notice.settings) box.append(h("button", { class: "btn", onclick: () => chrome.runtime.openOptionsPage() }, "Open settings"));
  }

  const layers = [layerCpu(), layerStatic(state), layerDynamic(state), layerNetwork(state), layerVt(state)];
  if (!autoOpened && state) {
    const firstAlert = layers.find((l) => l.status === "alert");
    if (firstAlert) open.add(firstAlert.id); // open only the first flagged layer
    autoOpened = true;
  }
  $("layers").replaceChildren(...layers.map((layer) => {
    const isOpen = open.has(layer.id);
    const bodyId = "layer-body-" + layer.id;
    const toggle = () => { if (open.has(layer.id)) open.delete(layer.id); else open.add(layer.id); render(); };
    // The whole row is clickable; the button inside is what keyboards and screen readers use.
    const head = h("div", { class: "layer-head" + (isOpen ? " open" : ""), onclick: toggle },
      h("button", {
        class: "layer-toggle", "aria-expanded": String(isOpen), "aria-controls": bodyId,
        onclick: (e) => { e.stopPropagation(); toggle(); }
      },
        h("span", { class: "layer-title" }, layer.title),
        h("span", { class: "layer-sum" }, layer.summary)),
      h("span", { class: "chip " + layer.status }, layer.chip),
      h("span", { class: "caret", "aria-hidden": "true" })
    );
    const body = h("div", { class: "layer-body", id: bodyId, hidden: !isOpen }, layer.body);
    return h("li", { class: "layer", "data-status": layer.status }, h("span", { class: "node", "aria-hidden": "true" }), head, body);
  }));

  $("scanBtn").disabled = busy.scan || tabId == null;
  $("scanBtn").textContent = busy.scan ? "Scanning…" : "Scan this page now";
  $("measureBtn").disabled = busy.measure || tabId == null;
  $("measureBtn").textContent = busy.measure ? "Measuring (8 s)…" : "Measure this tab";
  $("vtBtn").disabled = busy.vt || tabId == null;
  $("vtBtn").textContent = busy.vt ? "Checking (takes a while)…" : "Check with VirusTotal";
}

// ---------- data ----------
let lastCpuSample = null;

// Needs two readings to get a percent, so the first tick shows "Reading…".
async function sampleCpuPercent() {
  try {
    const info = await chrome.system.cpu.getInfo();
    const procs = info.processors.map((p) => ({ idle: p.usage.idle, total: p.usage.total }));
    let percent = null;
    if (lastCpuSample && lastCpuSample.length === procs.length) {
      let used = 0, total = 0;
      procs.forEach((p, i) => {
        const dTotal = p.total - lastCpuSample[i].total;
        const dIdle = p.idle - lastCpuSample[i].idle;
        if (dTotal > 0) { used += dTotal - dIdle; total += dTotal; }
      });
      percent = total > 0 ? Math.round((used / total) * 100) : null;
    }
    lastCpuSample = procs;
    return percent;
  } catch (e) {
    return null;
  }
}

async function refreshSystem() {
  latest.cpu = await sampleCpuPercent();
  try {
    const mem = await chrome.system.memory.getInfo();
    latest.memTotal = mem.capacity;
    latest.memUsed = mem.capacity - mem.availableCapacity;
  } catch (e) {}
  render();
}

async function refreshState() {
  if (tabId == null) return;
  try {
    const resp = await chrome.runtime.sendMessage({ type: "GET_STATE", tabId });
    latest.state = (resp && resp.state) || null;
  } catch (e) {
    latest.state = null;
  }
  render();
}

function relevantIndicators(state) {
  const set = new Set();
  if (!state) return set;
  if (state.hostname) set.add(state.hostname);
  Object.entries(state.requestsByHost || {}).forEach(([host, rec]) => {
    set.add(host);
    (rec.ips || []).forEach((ip) => set.add(ip));
  });
  return set;
}

async function loadVtRows() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: "GET_VT_RESULTS" });
    const wanted = relevantIndicators(latest.state);
    vtRows = ((resp && resp.results) || []).filter((r) => wanted.has(r.indicator));
  } catch (e) {
    vtRows = [];
  }
  render();
}

// ---------- buttons ----------
$("scanBtn").addEventListener("click", async () => {
  busy.scan = true; notice = null; render();
  let ok = false;
  try {
    const resp = await chrome.runtime.sendMessage({ type: "LAYER1_SCAN_NOW", tabId });
    ok = !!(resp && resp.ok);
  } catch (e) {}
  busy.scan = false;
  if (!ok) notice = { text: "JackTrap can’t read this page yet. Reload it once and scan again. Browser pages such as chrome:// can’t be scanned." };
  open.add("static");
  await refreshState();
});

$("measureBtn").addEventListener("click", async () => {
  busy.measure = true; notice = null; render();
  try {
    const resp = await chrome.runtime.sendMessage({ type: "LAYER2_MEASURE_NOW", tabId, seconds: 8 });
    if (!resp || !resp.ok) {
      const error = resp && resp.error;
      if (error === "no_permission") notice = { text: "Turn on “Precise per-tab measurement” in settings first. Chrome will ask your permission.", settings: true };
      else if (error === "busy") notice = { text: "A measurement is already running for this tab." };
      else notice = { text: "JackTrap could not measure this tab. Another tool may be attached to it, or it is a browser page such as chrome://." };
    }
  } catch (e) {
    notice = { text: "The measurement was interrupted. Try again." };
  }
  busy.measure = false;
  open.add("behavior");
  await refreshState();
});

$("vtBtn").addEventListener("click", async () => {
  busy.vt = true; notice = null; render();
  try {
    const resp = await chrome.runtime.sendMessage({ type: "SCAN_VT", tabId });
    if (!resp || resp.error === "no_state") {
      notice = { text: "No data for this tab yet. Reload the page and try again." };
    } else {
      const all = [...(resp.domainResults || []), ...(resp.ipResults || [])];
      if (all.some((r) => r && r.error === "no_api_key")) {
        notice = { text: "Add a VirusTotal API key in settings to use this check.", settings: true };
      }
    }
  } catch (e) {
    notice = { text: "The VirusTotal check failed. Try again in a minute." };
  }
  busy.vt = false;
  open.add("vt");
  await refreshState();
  await loadVtRows();
});

$("settingsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("dashBtn").addEventListener("click", () => chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") }));

// ---------- start ----------
(async function start() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab ? tab.id : null;
  render();
  await refreshState();
  await loadVtRows();
  refreshSystem();
  setInterval(refreshState, 3000);
  setInterval(refreshSystem, 3000);
})();
