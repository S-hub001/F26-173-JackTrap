# JackTrap (Chrome MV3)

A minimal browser extension that watches for cryptojacking-style behavior per
open site, and cross-checks the domains/IPs it sees against VirusTotal.

## What it actually does (and doesn't)

Browser extensions run inside a sandbox with **no API to read OS processes,
per-process CPU/RAM, or hash an arbitrary running executable**. This is true
on every Chrome channel, including plain stable Chrome with no flags — it's
not a "switch to Canary/Dev" situation. Chrome's only API that exposes that
level of detail, `chrome.processes`, is restricted to extensions that are
force-installed by enterprise policy; a normal unpacked or Web Store install
never gets it, on any channel. Going further would require a separate native
application talking to the OS (Native Messaging).

What a normal extension *can* get, and what this one uses:

**Whole-machine CPU & memory** (`chrome.system.cpu`, `chrome.system.memory`
— available on stable Chrome, no special install needed)
- Shown live in the popup and in a dashboard panel, refreshed every few
  seconds while either is open
- This is system-wide, not per-tab — there's no way for an extension to
  attribute it to one tab. The intended use is correlation: if this spikes
  at the same time one specific tracked tab's WASM/Worker/long-task numbers
  spike, that combination is a much stronger signal than either alone
- The background worker also samples this once a minute via `chrome.alarms`
  (so it keeps working even with no popup/dashboard open) and logs a
  `system_cpu_high` event when usage crosses 85%, tagging whichever tracked
  tab currently has the highest suspicion score as a best-effort hint — not
  a confirmed cause

And per open tab, the closest legitimate signals a browser *can* see:

**Network artifacts** (`background.js`, `webRequest` API)
- Every host contacted, request count, resolved IP (where Chrome exposes it),
  ports, and request types
- Flags connections to known stratum/mining-pool ports (3333, 4444, 5555,
  7777, 8080, 9999, 14444, etc.) or hostnames containing mining-related
  keywords (xmr, monero, stratum, nanopool, coinhive, cryptonight, etc.)

**In-page resource-abuse heuristics** (`page-hook.js`, injected into the
page's real JS context)
- `WebAssembly.instantiate/compile` call counts — most browser miners run as
  WASM for speed
- `Worker` creation counts and filenames — miners often run in a background
  Worker to survive tab throttling
- `WebSocket` connections and their destination host/port — the stratum
  mining protocol is frequently tunneled over WebSocket
- Long-task blocking (`PerformanceObserver` `longtask` entries) — sustained
  main-thread saturation is a strong CPU-abuse proxy since extensions can't
  read real per-tab CPU%
- JS heap growth via `performance.memory` sampling (Chrome-only, coarse)

These combine into a 0–100 suspicion score shown in the popup and as a
toolbar badge, per tab, reset on each new page navigation.

**VirusTotal (signature-based reputation only)**
- Looks up the page's own host, any flagged suspicious hosts, and their
  resolved IPs against VT's `/domains` and `/ip_addresses` endpoints
- Reads `last_analysis_stats` (malicious/suspicious/harmless/undetected
  counts) — this is signature/vendor-verdict based, not the extension doing
  its own detection
- Capped at 5 domain + 3 IP lookups per click, 16s apart, with a 1-hour
  cache, to stay under the free API's ~4 req/min limit

## Full dashboard (all tabs + logs)

The popup shows one tab at a time. Click **"Open full dashboard (all tabs + logs)"**
at the bottom of the popup to open `dashboard.html` in its own browser tab, which shows:

- **Tracked tabs** — every tab JackTrap currently has signals for, sorted by
  suspicion score, with the same WASM/Worker/WebSocket/long-task counts as
  the popup but side by side across tabs.
- **Event log** — a persistent, filterable timeline (stored in
  `chrome.storage.local`, capped at 300 entries) of new suspicious
  connections, score-tier crossings (elevated/high), VirusTotal scan
  results, and system-wide CPU spikes (≥85%), across all tabs, that
  survives popup closes and service-worker restarts until you clear it.

## Install (unpacked)

1. `chrome://extensions`
2. Enable "Developer mode" (top right)
3. "Load unpacked" → select this folder
4. Click the toolbar icon on any site to see its score; open the extension's
   **Options** page to set/replace your VirusTotal API key

## Known limitations

- Service workers in MV3 can be terminated when idle; per-tab stats are kept
  in memory only, so a long-idle tab's history may reset on next activity.
- `performance.memory` is coarse and Chrome-only.
- VT free-tier rate limits mean a full scan of a page with many hosts will
  only check the top few per click — click again to check more (results are
  cached).
- This is a detection *aid*, not a guarantee — false positives (e.g. a
  legitimate site that happens to use WASM/Workers heavily) and false
  negatives (well-obfuscated miners) are both possible.
