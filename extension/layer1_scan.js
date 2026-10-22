// Layer 1, page side. Runs in every page (isolated world) after it loads.
// It only READS the page: it collects the text of inline <script> tags and the
// addresses of external script files, then hands them to the background worker.
// New <script> tags added in the first minute are sent too (miners often
// inject themselves late).
(() => {
  const MAX_INLINE_PER_SCRIPT = 200000;
  const MAX_INLINE_TOTAL = 400000;
  const MAX_URLS = 60;
  const WATCH_MS = 60000;

  function isCodeType(type) {
    const t = (type || '').trim().toLowerCase();
    return !t || t === 'module' || /javascript|ecmascript/.test(t);
  }

  function collect(nodes, seen) {
    const inline = [];
    const urls = [];
    let budget = MAX_INLINE_TOTAL;
    for (const node of nodes) {
      if (seen) {
        if (seen.has(node)) continue;
        seen.add(node);
      }
      if (!isCodeType(node.type)) continue;
      if (node.src) {
        if (urls.length < MAX_URLS) urls.push(node.src);
      } else if (node.textContent && budget > 0) {
        const text = node.textContent.slice(0, Math.min(MAX_INLINE_PER_SCRIPT, budget));
        budget -= text.length;
        inline.push(text);
      }
    }
    return { inline, urls };
  }

  function send(data, phase) {
    if (!data.inline.length && !data.urls.length) return;
    try {
      chrome.runtime.sendMessage({ type: 'LAYER1_PAGE_DATA', phase, inline: data.inline, urls: data.urls });
    } catch (e) {
      // the extension was reloaded; nothing to do
    }
  }

  // The popup's "Scan this page now" button asks for a fresh, full read.
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === 'LAYER1_COLLECT') {
      sendResponse(collect(document.querySelectorAll('script'), null));
    }
  });

  const seen = new WeakSet();
  send(collect(document.querySelectorAll('script'), seen), 'initial');

  // Watch for scripts added later, for a short time only (keeps it light).
  const pending = [];
  let timer = null;
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.tagName === 'SCRIPT') pending.push(n);
        else if (n.querySelectorAll) pending.push(...n.querySelectorAll('script'));
      }
    }
    if (pending.length && !timer) {
      timer = setTimeout(() => {
        timer = null;
        send(collect(pending.splice(0), seen), 'incremental');
      }, 1000);
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => observer.disconnect(), WATCH_MS);
})();
