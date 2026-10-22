/** @jest-environment jsdom */
// Runs the real page-hook.js inside jsdom and checks the Layer 2 sensors.
const fs = require('fs');
const path = require('path');

const code = fs.readFileSync(path.join(__dirname, '..', 'extension', 'page-hook.js'), 'utf8');

class FakeMemory { constructor(bytes) { this._bytes = bytes; } get buffer() { return { byteLength: this._bytes }; } }

function load() {
  jest.useFakeTimers();
  HTMLCanvasElement.prototype.getContext = function () { return null; }; // jsdom has no canvas
  window.postMessage = jest.fn();
  Object.defineProperty(navigator, 'hardwareConcurrency', { value: 8, configurable: true });
  Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
  window.Worker = class { terminate() {} };
  window.WebSocket = class {};
  window.WebAssembly = {
    Memory: FakeMemory,
    instantiate: async () => ({ instance: { exports: { memory: new FakeMemory(3 * 65536) } } }),
    instantiateStreaming: async () => ({ instance: { exports: {} } }),
    compile: async () => ({})
  };
  window.eval(code);
}

const lastPayload = () => {
  const calls = window.postMessage.mock.calls;
  return calls[calls.length - 1][0].payload;
};

afterEach(() => { jest.useRealTimers(); });

test('sends a dynamic block every 4 seconds with event loop checks', () => {
  load();
  jest.advanceTimersByTime(4100);
  const payload = lastPayload();
  expect(payload.dynamic).toBeDefined();
  expect(payload.dynamic.visible).toBe(true);
  expect(payload.dynamic.loopSamples).toBeGreaterThanOrEqual(30);   // about 40 checks in 4 s
  expect(payload.dynamic.loopLagP95Ms).toBeLessThan(5);             // nothing blocked it
  expect(payload.dynamic.cores).toBe(8);
});

test('the older telemetry fields are still sent', () => {
  load();
  new window.Worker('a.js');
  jest.advanceTimersByTime(4100);
  const payload = lastPayload();
  expect(payload.workersCreated).toBe(1);
  expect(payload).toHaveProperty('longTaskTotalMs');
});

test('counts live workers and the peak, and forgets ended ones', () => {
  load();
  const a = new window.Worker('a.js');
  new window.Worker('b.js');
  new window.Worker('c.js');
  a.terminate();
  a.terminate(); // twice must not count twice
  jest.advanceTimersByTime(4100);
  const d = lastPayload().dynamic;
  expect(d.workersLive).toBe(2);
  expect(d.workersPeak).toBe(3);
});

test('a hidden tab is reported as not visible and collects no timer checks', () => {
  load();
  Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
  jest.advanceTimersByTime(4100);
  const d = lastPayload().dynamic;
  expect(d.visible).toBe(false);
  expect(d.loopSamples).toBe(0);
});

test('counts canvas, WebGL and WebGPU requests', () => {
  load();
  const canvas = document.createElement('canvas');
  canvas.getContext('2d'); canvas.getContext('webgl'); canvas.getContext('webgl2'); canvas.getContext('webgpu');
  jest.advanceTimersByTime(4100);
  const gpu = lastPayload().dynamic.gpu;
  expect(gpu).toMatchObject({ canvas2d: 1, webgl: 1, webgl2: 1, webgpu: 1 });
});

test('sees WebAssembly memory passed in imports and exported by the module', async () => {
  load();
  const imported = new window.WebAssembly.Memory(10 * 65536);
  await window.WebAssembly.instantiate(new Uint8Array(), { env: { memory: imported } });
  await Promise.resolve();
  jest.advanceTimersByTime(4100);
  const d = lastPayload().dynamic;
  expect(d.wasmMemories).toBe(2);                                    // one imported, one exported
  expect(d.wasmMemoryBytes).toBe(10 * 65536 + 3 * 65536);
});

test('the hooked WebAssembly.instantiate still returns the real result', async () => {
  load();
  const result = await window.WebAssembly.instantiate(new Uint8Array(), {});
  expect(result.instance.exports.memory).toBeInstanceOf(FakeMemory);
});

test('a failing instantiate still rejects for the page (no swallowed errors)', async () => {
  load();
  window.WebAssembly.instantiate = async () => { throw new Error('bad module'); };
  // reinstall the hook on the failing function
  jest.resetModules();
  window.eval(code);
  await expect(window.WebAssembly.instantiate(new Uint8Array(), {})).rejects.toThrow('bad module');
});
