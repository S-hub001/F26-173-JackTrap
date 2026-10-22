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
      return origInstantiate.apply(this, args);
    };
    const origInstantiateStreaming = WebAssembly.instantiateStreaming;
    if (origInstantiateStreaming) {
      WebAssembly.instantiateStreaming = function (...args) {
        telemetry.wasmInstantiations++;
        return origInstantiateStreaming.apply(this, args);
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
      return new OrigWorker(scriptURL, options);
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
    window.postMessage({ __cjs_telemetry: true, payload: JSON.parse(JSON.stringify(telemetry)) }, "*");
    // reset per-interval counters that should represent *rate*, keep cumulative ones
    telemetry.longTasks = 0;
    telemetry.longTaskTotalMs = 0;
  }

  setInterval(pushTelemetry, 4000);
})();
