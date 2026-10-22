// Runs the real background.js in a sandbox with a fake chrome object.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const extDir = path.join(__dirname, '..', 'extension');
const read = (name) => fs.readFileSync(path.join(extDir, name), 'utf8');

async function loadBackground({ fetchImpl, settings } = {}) {
  const store = {};
  if (settings) store.jacktrap_settings = settings;
  const handlers = {};
  const on = (name) => ({ addListener: (fn) => { handlers[name] = fn; } });
  let cpuCall = 0;

  const ctx = vm.createContext({
    console, URL, TextDecoder, AbortController, Promise, JSON, Math, Date, Object, Array, Set, Map,
    setTimeout: (fn) => { fn(); return 0; }, clearTimeout: () => {},
    fetch: fetchImpl || (async () => ({ ok: false })),
    chrome: {
      webRequest: { onCompleted: on('webRequest') },
      webNavigation: { onCommitted: on('navigation') },
      tabs: {
        onRemoved: on('tabRemoved'),
        get: async () => ({ url: 'https://evil.test/page' }),
        query: async () => [{ id: 1 }],
        sendMessage: async () => ({ inline: ['var lib = "coinhive";'], urls: ['https://cdn.test/app.js'] })
      },
      runtime: { onMessage: on('message'), onInstalled: on('installed') },
      alarms: { onAlarm: on('alarm'), get: async () => null, create: async () => {} },
      storage: {
        onChanged: on('storage'),
        local: {
          get: async (key) => (key == null ? { ...store } : typeof key === 'string' ? { [key]: store[key] } : { ...store }),
          set: async (obj) => { Object.assign(store, obj); },
          remove: async () => {}
        }
      },
      action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
      system: {
        cpu: { getInfo: async () => { cpuCall++; return { processors: [{ usage: { idle: 100 + cpuCall * 40, total: 200 + cpuCall * 100 } }] }; } },
        memory: { getInfo: async () => ({ capacity: 16e9, availableCapacity: 8e9 }) }
      }
    }
  });
  ctx.importScripts = (...files) => files.forEach((f) => vm.runInContext(read(f), ctx, { filename: f }));
  vm.runInContext(read('background.js'), ctx, { filename: 'background.js' });
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));

  const send = (msg, sender) => new Promise((resolve) => {
    const keep = handlers.message(msg, sender || {}, resolve);
    if (!keep) resolve(undefined);
  });
  return { ctx, store, send, handlers };
}

const tab = { tab: { id: 1 } };
const getState = async (b) => (await b.send({ type: 'GET_STATE', tabId: 1 })).state;

test('no API key is stored in the code', () => {
  expect(read('background.js')).not.toMatch(/[0-9a-f]{64}/i);
  expect(read('options.js')).not.toMatch(/[0-9a-f]{64}/i);
});

test('system CPU is a percent after startup', async () => {
  const b = await loadBackground();
  const cpu = vm.runInContext('systemUsage.cpuPercent', b.ctx);
  expect(cpu).toBeGreaterThanOrEqual(0);
  expect(cpu).toBeLessThanOrEqual(100);
});

test('strong words in inline code raise the score and write a log entry', async () => {
  const b = await loadBackground();
  await b.send({ type: 'LAYER1_PAGE_DATA', phase: 'initial', inline: ['new CoinHive.Anonymous("k"); miner.start();'], urls: [] }, tab);
  const state = await getState(b);
  expect(state.layer1.level).toBe('strong');
  expect(state.layer1.points).toBe(15 + 7 * 2);
  expect(state.score).toBeGreaterThanOrEqual(29);
  const log = b.store.jacktrap_eventLog;
  expect(log.some((e) => e.type === 'static_scan')).toBe(true);
});

test('script files are NOT downloaded while the CPU is calm', async () => {
  const fetchImpl = jest.fn(async () => ({ ok: false }));
  const b = await loadBackground({ fetchImpl });
  vm.runInContext('systemUsage.cpuPercent = 5', b.ctx);
  await b.send({ type: 'LAYER1_PAGE_DATA', inline: [], urls: ['https://cdn.test/app.js'] }, tab);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect((await getState(b)).layer1.externalQueue).toEqual(['https://cdn.test/app.js']);
});

test('script files ARE downloaded and scanned when the CPU is busy', async () => {
  const body = new TextEncoder().encode('algo: "cryptonight"');
  const fetchImpl = jest.fn(async () => ({
    ok: true,
    body: { getReader: () => { let done = false; return { read: async () => (done ? { done: true } : ((done = true), { done: false, value: body })) }; } }
  }));
  const b = await loadBackground({ fetchImpl });
  vm.runInContext('systemUsage.cpuPercent = 80', b.ctx);
  await b.send({ type: 'LAYER1_PAGE_DATA', inline: [], urls: ['https://cdn.test/app.js'] }, tab);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
  expect(fetchImpl.mock.calls[0][1].credentials).toBe('omit');
  const l1 = (await getState(b)).layer1;
  expect(l1.hits.map((h) => h.keyword)).toContain('cryptonight');
  expect(l1.externalDone).toBe(1);
});

test('"Scan this page now" reads script files even when the CPU is calm', async () => {
  const body = new TextEncoder().encode('stratum+tcp://pool.example:3333');
  const fetchImpl = jest.fn(async () => ({
    ok: true,
    body: { getReader: () => { let done = false; return { read: async () => (done ? { done: true } : ((done = true), { done: false, value: body })) }; } }
  }));
  const b = await loadBackground({ fetchImpl });
  vm.runInContext('systemUsage.cpuPercent = 3', b.ctx);
  const resp = await b.send({ type: 'LAYER1_SCAN_NOW', tabId: 1 });
  expect(resp.ok).toBe(true);
  const l1 = (await getState(b)).layer1;
  expect(l1.level).toBe('strong');
  expect(l1.hits.map((h) => h.keyword)).toEqual(expect.arrayContaining(['coinhive', 'stratum+tcp']));
});

test('a failed download is counted, not fatal', async () => {
  const b = await loadBackground({ fetchImpl: async () => { throw new Error('network'); } });
  vm.runInContext('systemUsage.cpuPercent = 90', b.ctx);
  await b.send({ type: 'LAYER1_PAGE_DATA', inline: [], urls: ['https://cdn.test/a.js'] }, tab);
  const l1 = (await getState(b)).layer1;
  expect(l1.externalFailed).toBe(1);
  expect(l1.level).toBe('clean');
});

test('turning the scanner off in settings disables Layer 1', async () => {
  const b = await loadBackground({ settings: { layer1Enabled: false } });
  await b.send({ type: 'LAYER1_PAGE_DATA', inline: ['coinhive'], urls: [] }, tab);
  const state = await getState(b);
  expect(state.layer1.disabled).toBe(true);
  expect(state.layer1.points).toBe(0);
});

test('a word switched off in settings is not matched', async () => {
  const b = await loadBackground({ settings: { disabledKeywords: ['coinhive'] } });
  await b.send({ type: 'LAYER1_PAGE_DATA', inline: ['coinhive'], urls: [] }, tab);
  expect((await getState(b)).layer1.level).toBe('clean');
});
