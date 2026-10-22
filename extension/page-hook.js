// Runs in the MAIN world (real page context) so it can observe what the
// page itself does — not just what the extension can see from outside.
// It only *counts/observes*; it never blocks anything from this layer.
(() => {
  const telemetry = {
    wasmInstantiations: 0,
    workersCreated: 0,
    suspiciousWorkerNames: [],
    websockets: [],       // {url, host, port}
    longTasks: 0,          // count of >50ms main-thread blocking tasks
    longTaskTotalMs: 0,
    memorySamples: [],     // last few performance.memory.usedJSHeapSize readings
  };

  // ===================================================================
  // Layer 2 sensors: what is THIS page doing to the browser right now?
  // Everything here only observes. numbers are sent as telemetry.dynamic
  // ===================================================================
  let lastPush = performance.now();

  const L2 = (() => {
    const LOOP_MS = 100;            // ask "are you awake?" every 100 ms
    const FRAME_BURST_MS = 500;     // look at frames for half a second per window
    const lags = [];                // how late each check ran (ms) in this window
    let lastTick = performance.now();

    // event loop delay: a timer that should fire every LOOP_MS. If the page keeps the
    // main thread busy, the timer fires late. Late by X ms = the event loop was stuck X ms.
    function tick() {
      const now = performance.now();
      if (document.visibilityState === "visible") {
        if (lags.length < 400) lags.push(Math.max(0, now - lastTick - LOOP_MS));
      }
      lastTick = now;
      setTimeout(tick, LOOP_MS);
    }
    setTimeout(tick, LOOP_MS);
    document.addEventListener("visibilitychange", () => {
      lastTick = performance.now(); // the first check after a tab switch is not real lag
      lags.length = 0;
    });

    // frames: a short requestAnimationFrame burst once per window (not all the time,
    // because asking for frames constantly would keep an idle page awake).
    let frameResult = { fps: 0, slowFrames: 0, frameSamples: 0 };
    function frameBurst() {
      if (document.visibilityState !== "visible" || typeof requestAnimationFrame !== "function") return;
      let frames = 0, slow = 0, prev = 0;
      const start = performance.now();
      const step = (ts) => {
        frames++;
        if (prev && ts - prev > 50) slow++;
        prev = ts;
        if (ts - start < FRAME_BURST_MS) requestAnimationFrame(step);
        else frameResult = { fps: Math.round((frames / Math.max(1, ts - start)) * 1000), slowFrames: slow, frameSamples: frames };
      };
      requestAnimationFrame(step);
    }

    // workers alive (Chrome does not tell extensions a thread count; this is the closest)
    let liveWorkers = 0;
    let peakWorkers = 0;
    function workerStarted(worker) {
      liveWorkers++;
      if (liveWorkers > peakWorkers) peakWorkers = liveWorkers;
      try {
        let ended = false;
        const origTerminate = worker.terminate;
        worker.terminate = function () {
          if (!ended) { ended = true; liveWorkers = Math.max(0, liveWorkers - 1); }
          return origTerminate.apply(this, arguments);
        };
      } catch (e) {}
    }

    // WebAssembly memory we can see (passed in imports or exported by the module)
    const wasmMems = new WeakSet();
    const wasmRefs = [];
    function trackMemory(mem) {
      try {
        if (mem && !wasmMems.has(mem) && typeof WebAssembly !== "undefined" && mem instanceof WebAssembly.Memory) {
          wasmMems.add(mem);
          if (wasmRefs.length < 50) wasmRefs.push(new WeakRef(mem));
        }
      } catch (e) {}
    }
    function inspectImports(imports) {
      try {
        if (!imports || typeof imports !== "object") return;
        for (const mod of Object.values(imports)) {
          if (mod && typeof mod === "object") for (const v of Object.values(mod)) trackMemory(v);
        }
      } catch (e) {}
    }
    function inspectResult(result) {
      try {
        const instance = result && (result.instance || result);
        const exp = instance && instance.exports;
        if (exp) for (const v of Object.values(exp)) trackMemory(v);
      } catch (e) {}
    }
    function wasmBytes() {
      let total = 0, count = 0;
      for (const ref of wasmRefs) {
        const mem = ref.deref();
        if (mem) { try { total += mem.buffer.byteLength; count++; } catch (e) {} }
      }
      return { total, count };
    }

    // GPU: Chrome gives extensions no GPU %. We count who asked for GPU-backed contexts.
    const gpu = { canvas2d: 0, webgl: 0, webgl2: 0, webgpu: 0, adapterRequests: 0 };
    try {
      const origGetContext = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function (type) {
        if (type === "2d") gpu.canvas2d++;
        else if (type === "webgl" || type === "experimental-webgl") gpu.webgl++;
        else if (type === "webgl2") gpu.webgl2++;
        else if (type === "webgpu") gpu.webgpu++;
        return origGetContext.apply(this, arguments);
      };
    } catch (e) {}
    try {
      if (navigator.gpu && navigator.gpu.requestAdapter) {
        const origRequest = navigator.gpu.requestAdapter.bind(navigator.gpu);
        navigator.gpu.requestAdapter = function () { gpu.adapterRequests++; return origRequest.apply(null, arguments); };
      }
    } catch (e) {}

    // Called once per telemetry window.
    function collect(windowMs, longTaskMs) {
      const sorted = lags.splice(0).sort((a, b) => a - b);
      const n = sorted.length;
      const at = (q) => (n ? sorted[Math.min(n - 1, Math.floor(q * n))] : 0);
      const avg = n ? sorted.reduce((a, b) => a + b, 0) / n : 0;
      const mem = (typeof performance !== "undefined" && performance.memory) || {};
      const wasm = wasmBytes();
      const out = {
        visible: document.visibilityState === "visible",
        windowMs,
        loopSamples: n,
        loopLagAvgMs: avg,
        loopLagP95Ms: at(0.95),
        loopLagMaxMs: n ? sorted[n - 1] : 0,
        busyPct: windowMs > 0 ? Math.min(100, (longTaskMs / windowMs) * 100) : 0,
        fps: frameResult.fps,
        slowFrames: frameResult.slowFrames,
        frameSamples: frameResult.frameSamples,
        heapUsed: mem.usedJSHeapSize || 0,
        heapTotal: mem.totalJSHeapSize || 0,
        heapLimit: mem.jsHeapSizeLimit || 0,
        wasmMemoryBytes: wasm.total,
        wasmMemories: wasm.count,
        workersLive: liveWorkers,
        workersPeak: peakWorkers,
        cores: navigator.hardwareConcurrency || 0,
        gpu: Object.assign({}, gpu)
      };
      frameBurst(); // measure frames for the next window
      return out;
    }

    return { collect, workerStarted, inspectImports, inspectResult };
  })();

  const MINING_KEYWORDS = [
    "xmr", "monero", "stratum", "cryptonight", "nanopool", "minexmr",
    "supportxmr", "webmine", "coinimp", "crypto-loot", "cryptoloot",
    "authedmine", "coinhive", "minero", "jsecoin", "webminepool", "hashvault"
  ];
  const SUSPICIOUS_PORTS = new Set([
    3333, 3357, 4444, 4028, 5555, 5730, 7777, 8080, 8118, 8888,
    9999, 14444, 14433, 45560, 45700
  ]);

  function flagIfSuspicious(hostname, port) {
    const h = (hostname || "").toLowerCase();
    const kw = MINING_KEYWORDS.some(k => h.includes(k));
    const portHit = port && SUSPICIOUS_PORTS.has(Number(port));
    return kw || portHit;
  }

  // --- Hook WebAssembly ---
  try {
    const origInstantiate = WebAssembly.instantiate;
    WebAssembly.instantiate = function (...args) {
      telemetry.wasmInstantiations++;
      L2.inspectImports(args[1]);
      const promise = origInstantiate.apply(this, args);
      try { promise.then(L2.inspectResult, () => {}); } catch (e) {} // side look only
      return promise;
    };
    const origInstantiateStreaming = WebAssembly.instantiateStreaming;
    if (origInstantiateStreaming) {
      WebAssembly.instantiateStreaming = function (...args) {
        telemetry.wasmInstantiations++;
        L2.inspectImports(args[1]);
        const promise = origInstantiateStreaming.apply(this, args);
        try { promise.then(L2.inspectResult, () => {}); } catch (e) {}
        return promise;
      };
    }
    const origCompile = WebAssembly.compile;
    WebAssembly.compile = function (...args) {
      telemetry.wasmInstantiations++;
      return origCompile.apply(this, args);
    };
  } catch (e) {}

  // --- Hook Worker ---
  try {
    const OrigWorker = window.Worker;
    window.Worker = function (scriptURL, options) {
      telemetry.workersCreated++;
      const url = String(scriptURL || "");
      if (MINING_KEYWORDS.some(k => url.toLowerCase().includes(k))) {
        telemetry.suspiciousWorkerNames.push(url);
      }
      const worker = new OrigWorker(scriptURL, options);
      L2.workerStarted(worker); // Layer 2: count it as alive until terminate()
      return worker;
    };
    window.Worker.prototype = OrigWorker.prototype;
  } catch (e) {}

  // --- Hook WebSocket (common relay for stratum mining protocol over ws) ---
  try {
    const OrigWebSocket = window.WebSocket;
    window.WebSocket = function (url, protocols) {
      try {
        const u = new URL(url, location.href);
        const entry = { url: u.href, host: u.hostname, port: u.port || (u.protocol === "wss:" ? 443 : 80) };
        entry.suspicious = flagIfSuspicious(entry.host, entry.port) || u.href.toLowerCase().includes("stratum");
        telemetry.websockets.push(entry);
      } catch (e) {}
      return protocols !== undefined ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
  } catch (e) {}

  // --- Long-task observer (main-thread blocking, classic miner symptom) ---
  try {
    if ("PerformanceObserver" in window) {
      const po = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          telemetry.longTasks++;
          telemetry.longTaskTotalMs += entry.duration;
        }
      });
      po.observe({ entryTypes: ["longtask"] });
    }
  } catch (e) {}

  // --- Periodic memory sampling (Chrome-only, coarse) ---
  function sampleMemory() {
    try {
      if (performance.memory) {
        telemetry.memorySamples.push({
          t: Date.now(),
          used: performance.memory.usedJSHeapSize
        });
        if (telemetry.memorySamples.length > 12) telemetry.memorySamples.shift();
      }
    } catch (e) {}
  }

  // --- Push telemetry snapshot to the isolated content script every 4s ---
  function pushTelemetry() {
    sampleMemory();
    const now = performance.now();
    const dynamic = L2.collect(now - lastPush, telemetry.longTaskTotalMs); // Layer 2 numbers
    lastPush = now;
    window.postMessage({ __cjs_telemetry: true, payload: JSON.parse(JSON.stringify(Object.assign({}, telemetry, { dynamic }))) }, "*");
    // reset per-interval counters that should represent *rate*, keep cumulative ones
    telemetry.longTasks = 0;
    telemetry.longTaskTotalMs = 0;
  }

  setInterval(pushTelemetry, 4000);
})();
