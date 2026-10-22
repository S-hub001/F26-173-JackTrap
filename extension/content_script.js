// Isolated world: has chrome.runtime access, relays telemetry from
// page-hook.js (MAIN world, no chrome.* access) to the background worker.
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || !data.__cjs_telemetry) return;
  try {
    chrome.runtime.sendMessage({
      type: "TELEMETRY",
      origin: location.origin,
      href: location.href,
      payload: data.payload
    });
  } catch (e) {
    // extension context can be invalidated on reload; ignore
  }
});
