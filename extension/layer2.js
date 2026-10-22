// Layer 2: dynamic behavior analysis.
// Pure functions only (no Chrome APIs), so Node tests can run them.
//
// Where the numbers come from:
//   page   = sensors inside the page (page-hook.js): event loop delay, main-thread
//            busy %, frames, JS heap, WebAssembly memory, live workers, GPU contexts.
//            A hostile page could fake these.
//   process = measured from OUTSIDE the page with the debugger (Performance.getMetrics)
//            or chrome.processes (Dev channel only): CPU of the tab's process, etc.

const LAYER2_LIMITS = {
  windows: 12,                 // keep the last 12 telemetry windows (about 48 seconds)
  maxPoints: 30,               // Layer 2 can add at most this much to the 0-100 score
  wasmBigBytes: 64 * 1024 * 1024
};

function emptyLayer2() {
  return {
    level: 'calm',        // calm | busy | heavy
    points: 0,
    reasons: [],
    cores: null,
    page: null,           // latest numbers from inside the page
    windows: [],          // recent windows: { lagP95, busyPct }
    process: null,        // numbers measured from outside the page
    updatedAt: null,
    lastLoggedLevel: 'calm'
  };
}

// ---------- cleaning (the page is not trusted) ----------
function num(value, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(n, max);
}

function cleanDynamic(d) {
  d = d || {};
  const gpu = d.gpu || {};
  return {
    visible: d.visible === true,
    windowMs: num(d.windowMs, 600000),
    loopSamples: Math.round(num(d.loopSamples, 100000)),
    loopLagAvgMs: num(d.loopLagAvgMs, 60000),
    loopLagP95Ms: num(d.loopLagP95Ms, 60000),
    loopLagMaxMs: num(d.loopLagMaxMs, 600000),
    busyPct: num(d.busyPct, 100),
    fps: num(d.fps, 1000),
    slowFrames: Math.round(num(d.slowFrames, 100000)),
    frameSamples: Math.round(num(d.frameSamples, 100000)),
    heapUsed: num(d.heapUsed, 1e12),
    heapTotal: num(d.heapTotal, 1e12),
    heapLimit: num(d.heapLimit, 1e12),
    wasmMemoryBytes: num(d.wasmMemoryBytes, 1e13),
    wasmMemories: Math.round(num(d.wasmMemories, 10000)),
    workersLive: Math.round(num(d.workersLive, 100000)),
    workersPeak: Math.round(num(d.workersPeak, 100000)),
    cores: Math.round(num(d.cores, 1024)),
    gpu: {
      canvas2d: Math.round(num(gpu.canvas2d, 1e6)),
      webgl: Math.round(num(gpu.webgl, 1e6)),
      webgl2: Math.round(num(gpu.webgl2, 1e6)),
      webgpu: Math.round(num(gpu.webgpu, 1e6)),
      adapterRequests: Math.round(num(gpu.adapterRequests, 1e6))
    }
  };
}

// Adds one telemetry window from the page into the layer-2 state.
function mergeDynamic(l2, dynamic) {
  const d = cleanDynamic(dynamic);
  l2.page = d;
  if (d.cores) l2.cores = d.cores;
  // Only windows where the tab was visible and we got enough timer checks are trustworthy.
  if (d.visible && d.loopSamples >= 5) {
    l2.windows.push({ lagP95: d.loopLagP95Ms, busyPct: d.busyPct });
    if (l2.windows.length > LAYER2_LIMITS.windows) l2.windows.shift();
  }
  l2.updatedAt = Date.now();
  return l2;
}

// ---------- numbers measured from outside (debugger) ----------
function metricsToMap(metrics) {
  const map = {};
  for (const m of metrics || []) {
    if (m && typeof m.name === 'string' && typeof m.value === 'number' && Number.isFinite(m.value)) map[m.name] = m.value;
  }
  return map;
}

const round1 = (n) => (n == null ? null : Math.round(n * 10) / 10);

// series = array of metric maps taken a few seconds apart (first = start).
// Cumulative CPU-time metrics are turned into "% of one core":
//   100 = one core fully busy, 400 = four cores fully busy.
function processFromSeries(series, cores) {
  if (!series || series.length < 2) return null;
  const first = series[0];
  const last = series[series.length - 1];
  const dt = last.Timestamp - first.Timestamp;
  if (!(dt > 0)) return null;

  const rate = (a, b, name) => {
    const span = b.Timestamp - a.Timestamp;
    if (!(span > 0) || !(name in a) || !(name in b)) return null;
    return Math.max(0, ((b[name] - a[name]) / span) * 100);
  };

  const cpuPct = rate(first, last, 'ProcessTime');
  const mainRaw = rate(first, last, 'ThreadTime');
  const mainPct = mainRaw != null ? mainRaw : rate(first, last, 'TaskDuration');
  const otherPct = cpuPct != null && mainPct != null ? Math.max(0, cpuPct - mainPct) : null;

  let peak = null;
  for (let i = 1; i < series.length; i++) {
    const r = rate(series[i - 1], series[i], 'ProcessTime');
    if (r != null && (peak == null || r > peak)) peak = r;
  }

  // TaskDuration is only a fallback for ThreadTime, so it is only expected when ThreadTime is absent.
  const wanted = ['Timestamp', 'ProcessTime', 'ThreadTime', 'JSHeapUsedSize', 'JSHeapTotalSize', 'Nodes', 'WorkerGlobalScopes'];
  if (!('ThreadTime' in last)) wanted.push('TaskDuration');
  return {
    source: 'debugger',
    seconds: round1(dt),
    cpuPct: round1(cpuPct),
    cpuPeakPct: round1(peak),
    cpuMachinePct: cpuPct != null && cores ? round1(cpuPct / cores) : null,
    mainThreadPct: round1(mainPct),
    otherThreadsPct: round1(otherPct),
    scriptPct: round1(rate(first, last, 'ScriptDuration')),
    jsHeapUsed: 'JSHeapUsedSize' in last ? last.JSHeapUsedSize : null,
    jsHeapTotal: 'JSHeapTotalSize' in last ? last.JSHeapTotalSize : null,
    nodes: 'Nodes' in last ? last.Nodes : null,
    listeners: 'JSEventListeners' in last ? last.JSEventListeners : null,
    workers: 'WorkerGlobalScopes' in last ? last.WorkerGlobalScopes : null,
    missing: wanted.filter((name) => !(name in last)),
    measuredAt: Date.now()
  };
}

// Same shape, built from chrome.processes (Chrome Dev channel only).
function processFromNative(info, cores) {
  if (!info) return null;
  const cpu = typeof info.cpu === 'number' ? info.cpu : null; // % of one core
  return {
    source: 'chrome.processes',
    seconds: null,
    cpuPct: round1(cpu),
    cpuPeakPct: null,
    cpuMachinePct: cpu != null && cores ? round1(cpu / cores) : null,
    mainThreadPct: null,
    otherThreadsPct: null,
    scriptPct: null,
    jsHeapUsed: typeof info.jsMemoryUsed === 'number' ? info.jsMemoryUsed : null,
    jsHeapTotal: typeof info.jsMemoryAllocated === 'number' ? info.jsMemoryAllocated : null,
    privateMemory: typeof info.privateMemory === 'number' ? info.privateMemory : null,
    osPid: typeof info.osProcessId === 'number' ? info.osProcessId : null,
    nodes: null,
    listeners: null,
    workers: null,
    missing: [],
    measuredAt: Date.now()
  };
}

// ---------- scoring ----------
function median(values) {
  if (!values.length) return 0;
  const s = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// CPU alone never convicts: video and games are busy too. Points come from
// several signals, and the biggest bonus is for "many workers AND busy".
function scoreLayer2(l2) {
  const reasons = [];
  let points = 0;
  const cores = l2.cores || 4;
  const half = Math.max(2, Math.floor(cores / 2));
  const most = Math.max(2, cores - 1);
  let busyNow = false;

  const recent = l2.windows.slice(-3);
  if (recent.length >= 3) {
    const lag = median(recent.map((w) => w.lagP95));
    if (lag >= 200) { points += 8; busyNow = true; reasons.push('The page’s event loop runs about ' + Math.round(lag) + ' ms late'); }
    else if (lag >= 100) { points += 5; busyNow = true; reasons.push('The page’s event loop runs about ' + Math.round(lag) + ' ms late'); }
    else if (lag >= 50) { points += 2; reasons.push('The page’s event loop runs a little late (' + Math.round(lag) + ' ms)'); }

    const busy = median(recent.map((w) => w.busyPct));
    if (busy >= 50) { points += 8; busyNow = true; reasons.push('The main thread is blocked ' + Math.round(busy) + '% of the time'); }
    else if (busy >= 25) { points += 4; busyNow = true; reasons.push('The main thread is blocked ' + Math.round(busy) + '% of the time'); }
  }

  let manyWorkers = false;
  const p = l2.page;
  if (p) {
    if (p.workersLive >= most) { points += 8; manyWorkers = true; reasons.push(p.workersLive + ' workers alive (this machine has ' + cores + ' cores)'); }
    else if (p.workersLive >= half) { points += 4; manyWorkers = true; reasons.push(p.workersLive + ' workers alive (this machine has ' + cores + ' cores)'); }
    if (p.wasmMemoryBytes >= LAYER2_LIMITS.wasmBigBytes) {
      points += 4;
      reasons.push('WebAssembly holds ' + Math.round(p.wasmMemoryBytes / 1048576) + ' MB');
    }
  }

  const proc = l2.process;
  if (proc && proc.cpuPct != null) {
    if (proc.cpuPct >= 150) { points += 8; busyNow = true; reasons.push('This tab’s process uses ' + Math.round(proc.cpuPct) + '% of one core'); }
    else if (proc.cpuPct >= 80) { points += 4; busyNow = true; reasons.push('This tab’s process uses ' + Math.round(proc.cpuPct) + '% of one core'); }
    if (proc.otherThreadsPct != null && proc.otherThreadsPct >= 100 && (proc.mainThreadPct == null || proc.mainThreadPct < 50)) {
      points += 4;
      reasons.push('Most CPU is spent off the main thread (workers), a common miner pattern');
    }
  }

  if (manyWorkers && busyNow) {
    points += 6;
    reasons.push('Many workers and heavy CPU together');
  }

  points = Math.min(LAYER2_LIMITS.maxPoints, points);
  const level = points >= 14 ? 'heavy' : points >= 5 ? 'busy' : 'calm';
  return { points, level, reasons };
}

if (typeof module !== 'undefined') {
  module.exports = {
    LAYER2_LIMITS, emptyLayer2, cleanDynamic, mergeDynamic, metricsToMap,
    processFromSeries, processFromNative, scoreLayer2, median
  };
}
