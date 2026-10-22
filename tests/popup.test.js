/** @jest-environment jsdom */
// Smoke test: runs the real popup.html + popup.js with a fake chrome object.
const fs = require('fs');
const path = require('path');

const ext = (name) => fs.readFileSync(path.join(__dirname, '..', 'extension', name), 'utf8');

function boot(state, { cpu = 20 } = {}) {
  document.documentElement.innerHTML = ext('popup.html').replace(/<script[\s\S]*?<\/script>/g, '');
  let call = 0;
  global.chrome = {
    tabs: { query: async () => [{ id: 7 }], create: jest.fn() },
    runtime: {
      getURL: (p) => p, openOptionsPage: jest.fn(),
      sendMessage: async (msg) => {
        if (msg.type === 'GET_STATE') return { state };
        if (msg.type === 'GET_VT_RESULTS') return { results: [] };
        if (msg.type === 'LAYER1_SCAN_NOW') return { ok: true };
        return {};
      }
    },
    system: {
      cpu: { getInfo: async () => { call++; return { processors: [{ usage: { idle: 100 + call * (100 - cpu), total: 200 + call * 100 } }] }; } },
      memory: { getInfo: async () => ({ capacity: 16e9, availableCapacity: 8e9 }) }
    }
  };
  jest.resetModules();
  window.eval(ext('popup.js'));
  return new Promise((r) => setTimeout(r, 30));
}

const baseState = {
  tabId: 7, hostname: 'evil.test', score: 48, telemetry: {}, requestsByHost: {},
  suspiciousConnections: [], vt: { checked: false },
  layer1: {
    level: 'strong', scannedAt: 1, inlineScanned: 2, externalDone: 1, externalFailed: 0, externalTotal: 3,
    externalQueue: ['a', 'b'], disabled: false,
    hits: [
      { keyword: 'coinhive', weight: 4, where: [{ label: 'inline script 1', kind: 'inline', snippet: 'lib: "coinhive", algo' }] },
      { keyword: 'worker', weight: 1, where: [{ label: 'inline script 2', kind: 'inline', snippet: 'new Worker(' }] }
    ]
  }
};

test('shows the tier, the score and the reason', async () => {
  await boot(baseState);
  expect(document.getElementById('verdict').dataset.tier).toBe('elevated');
  expect(document.getElementById('verdictWord').textContent).toBe('Worth a look');
  expect(document.getElementById('scoreText').textContent).toBe('48 / 100');
  expect(document.getElementById('verdictWhy').textContent).toContain('coinhive');
  expect(document.getElementById('marker').style.left).toBe('48%');
});

test('lists the five layers and opens the flagged one', async () => {
  await boot(baseState);
  const layers = document.querySelectorAll('#layers > li');
  expect(layers.length).toBe(5);
  const staticLayer = layers[1];
  expect(staticLayer.dataset.status).toBe('alert');
  expect(staticLayer.querySelector('.layer-toggle').getAttribute('aria-expanded')).toBe('true');
  expect(staticLayer.textContent).toContain('coinhive');
  expect(staticLayer.textContent).toContain('2 script files not read yet');
});

test('weak words are marked as not counted alone when the page is clean', async () => {
  const clean = JSON.parse(JSON.stringify(baseState));
  clean.score = 0; clean.layer1.level = 'clean'; clean.layer1.hits = [baseState.layer1.hits[1]]; clean.layer1.externalQueue = [];
  await boot(clean);
  expect(document.getElementById('verdictWord').textContent).toBe('Low risk');
  expect(document.querySelectorAll('#layers > li')[1].textContent).toContain('not counted alone');
});

test('untrusted text is never turned into HTML', async () => {
  const evil = JSON.parse(JSON.stringify(baseState));
  evil.hostname = '<img src=x onerror=alert(1)>';
  evil.layer1.hits[0].where[0].snippet = '<script>alert(1)</script>';
  await boot(evil);
  expect(document.querySelector('img')).toBeNull();
  expect(document.querySelector('.layers script')).toBeNull();
  expect(document.getElementById('pageHost').textContent).toBe('<img src=x onerror=alert(1)>');
});

test('page without data shows a calm empty state', async () => {
  await boot(null);
  expect(document.getElementById('verdictWord').textContent).toBe('Not scanned');
  expect(document.getElementById('marker').style.display).toBe('none');
});

test('toggling a layer changes aria-expanded', async () => {
  await boot(baseState);
  const head = document.querySelectorAll('#layers .layer-toggle')[0];
  expect(head.getAttribute('aria-expanded')).toBe('false');
  head.click();
  expect(document.querySelectorAll('#layers .layer-toggle')[0].getAttribute('aria-expanded')).toBe('true');
});
