const L2 = require('../extension/layer2.js');
const { emptyLayer2, mergeDynamic, processFromSeries, processFromNative, scoreLayer2, metricsToMap, median, cleanDynamic } = L2;

const win = (over = {}) => ({
  visible: true, loopSamples: 40, loopLagP95Ms: 10, loopLagMaxMs: 30, busyPct: 2, workersLive: 0, workersPeak: 0, cores: 8, ...over
});
function fill(l2, over, times = 3) {
  for (let i = 0; i < times; i++) mergeDynamic(l2, win(over));
  return l2;
}

describe('cleanDynamic', () => {
  test('keeps real numbers and drops junk', () => {
    const d = cleanDynamic({ loopLagP95Ms: 12.5, workersLive: '3', busyPct: 500, heapUsed: -1, gpu: { webgl: 2 } });
    expect(d.loopLagP95Ms).toBe(12.5);
    expect(d.workersLive).toBe(3);
    expect(d.busyPct).toBe(100);
    expect(d.heapUsed).toBe(0);
    expect(d.gpu.webgl).toBe(2);
  });
  test('missing input is fine', () => {
    expect(cleanDynamic(undefined).visible).toBe(false);
    expect(cleanDynamic(null).gpu.webgpu).toBe(0);
  });
});

describe('mergeDynamic', () => {
  test('keeps only the last 12 windows', () => {
    const l2 = emptyLayer2();
    for (let i = 0; i < 20; i++) mergeDynamic(l2, win({ loopLagP95Ms: i }));
    expect(l2.windows.length).toBe(12);
    expect(l2.windows[11].lagP95).toBe(19);
  });
  test('ignores windows from hidden tabs or with too few checks', () => {
    const l2 = emptyLayer2();
    mergeDynamic(l2, win({ visible: false }));
    mergeDynamic(l2, win({ loopSamples: 2 }));
    expect(l2.windows.length).toBe(0);
    expect(l2.page).not.toBeNull();
  });
  test('remembers the core count', () => {
    expect(mergeDynamic(emptyLayer2(), win({ cores: 12 })).cores).toBe(12);
  });
});

describe('scoreLayer2', () => {
  test('a calm page scores 0', () => {
    const r = scoreLayer2(fill(emptyLayer2(), {}));
    expect(r).toMatchObject({ points: 0, level: 'calm' });
  });
  test('needs 3 windows before judging the event loop', () => {
    expect(scoreLayer2(fill(emptyLayer2(), { loopLagP95Ms: 500 }, 2)).points).toBe(0);
  });
  test('one slow spike among calm windows does not count (median of 3)', () => {
    const l2 = emptyLayer2();
    mergeDynamic(l2, win()); mergeDynamic(l2, win({ loopLagP95Ms: 900 })); mergeDynamic(l2, win());
    expect(scoreLayer2(l2).points).toBe(0);
  });
  test('event loop delay bands: 50, 100, 200 ms', () => {
    expect(scoreLayer2(fill(emptyLayer2(), { loopLagP95Ms: 60 })).points).toBe(2);
    expect(scoreLayer2(fill(emptyLayer2(), { loopLagP95Ms: 120 })).points).toBe(5);
    expect(scoreLayer2(fill(emptyLayer2(), { loopLagP95Ms: 250 })).points).toBe(8);
  });
  test('main thread blocked: 25% and 50%', () => {
    expect(scoreLayer2(fill(emptyLayer2(), { busyPct: 30 })).points).toBe(4);
    expect(scoreLayer2(fill(emptyLayer2(), { busyPct: 55 })).points).toBe(8);
  });
  test('workers are compared with the number of cores', () => {
    expect(scoreLayer2(fill(emptyLayer2(), { workersLive: 4 })).points).toBe(4);   // half of 8 cores
    expect(scoreLayer2(fill(emptyLayer2(), { workersLive: 7 })).points).toBe(8);   // cores - 1
    expect(scoreLayer2(fill(emptyLayer2(), { workersLive: 2 })).points).toBe(0);
  });
  test('many workers + heavy CPU together gets the combo bonus', () => {
    const r = scoreLayer2(fill(emptyLayer2(), { workersLive: 7, busyPct: 60 }));
    expect(r.points).toBe(8 + 8 + 6);
    expect(r.level).toBe('heavy');
    expect(r.reasons.join(' ')).toMatch(/together/);
  });
  test('large WebAssembly memory adds a little', () => {
    expect(scoreLayer2(fill(emptyLayer2(), { wasmMemoryBytes: 100 * 1048576 })).points).toBe(4);
  });
  test('process CPU alone (video-like) is busy, not heavy', () => {
    const l2 = fill(emptyLayer2(), {});
    l2.process = { cpuPct: 90, mainThreadPct: 80, otherThreadsPct: 10 };
    const r = scoreLayer2(l2);
    expect(r.points).toBe(4);
    expect(r.level).toBe('calm');
  });
  test('CPU spent off the main thread is the miner pattern', () => {
    const l2 = fill(emptyLayer2(), {});
    l2.process = { cpuPct: 400, mainThreadPct: 10, otherThreadsPct: 390 };
    expect(scoreLayer2(l2).points).toBe(12);
  });
  test('never more than 30 points', () => {
    const l2 = fill(emptyLayer2(), { loopLagP95Ms: 900, busyPct: 90, workersLive: 8, wasmMemoryBytes: 1e9 });
    l2.process = { cpuPct: 800, mainThreadPct: 5, otherThreadsPct: 795 };
    expect(scoreLayer2(l2).points).toBe(30);
  });
});

describe('processFromSeries', () => {
  const sample = (t, pt, tt, extra = {}) => ({ Timestamp: t, ProcessTime: pt, ThreadTime: tt, ...extra });

  test('turns cumulative CPU seconds into percent of one core', () => {
    const p = processFromSeries([sample(0, 0, 0), sample(8, 12, 2)], 8);
    expect(p.cpuPct).toBe(150);
    expect(p.mainThreadPct).toBe(25);
    expect(p.otherThreadsPct).toBe(125);
    expect(p.cpuMachinePct).toBe(18.8);
    expect(p.seconds).toBe(8);
  });
  test('finds the busiest slice', () => {
    const p = processFromSeries([sample(0, 0, 0), sample(2, 1, 0.1), sample(4, 7, 0.2)], 4);
    expect(p.cpuPeakPct).toBe(300);
  });
  test('falls back to TaskDuration when ThreadTime is missing', () => {
    const p = processFromSeries([{ Timestamp: 0, ProcessTime: 0, TaskDuration: 0 }, { Timestamp: 4, ProcessTime: 4, TaskDuration: 1 }], 4);
    expect(p.mainThreadPct).toBe(25);
  });
  test('reports missing metrics instead of guessing', () => {
    const p = processFromSeries([{ Timestamp: 0 }, { Timestamp: 4 }], 4);
    expect(p.cpuPct).toBeNull();
    expect(p.missing).toEqual(expect.arrayContaining(['ProcessTime', 'ThreadTime']));
  });
  test('bad input gives null', () => {
    expect(processFromSeries(null, 4)).toBeNull();
    expect(processFromSeries([sample(0, 0, 0)], 4)).toBeNull();
    expect(processFromSeries([sample(5, 0, 0), sample(5, 1, 1)], 4)).toBeNull();
  });
  test('counters that go backwards never give negative CPU', () => {
    expect(processFromSeries([sample(0, 10, 5), sample(4, 2, 1)], 4).cpuPct).toBe(0);
  });
  test('passes heap, nodes and worker counts through', () => {
    const p = processFromSeries([sample(0, 0, 0), sample(4, 4, 1, { JSHeapUsedSize: 5e6, JSHeapTotalSize: 9e6, Nodes: 800, WorkerGlobalScopes: 3 })], 4);
    expect(p).toMatchObject({ jsHeapUsed: 5e6, jsHeapTotal: 9e6, nodes: 800, workers: 3 });
  });
});

describe('helpers', () => {
  test('metricsToMap ignores junk', () => {
    expect(metricsToMap([{ name: 'A', value: 1 }, { name: 'B', value: NaN }, null, { name: 5, value: 1 }])).toEqual({ A: 1 });
    expect(metricsToMap(undefined)).toEqual({});
  });
  test('median', () => {
    expect(median([])).toBe(0);
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 2, 3])).toBe(2.5);
  });
  test('processFromNative maps chrome.processes fields', () => {
    const p = processFromNative({ cpu: 250, privateMemory: 1e8, jsMemoryUsed: 2e7, jsMemoryAllocated: 3e7, osProcessId: 77 }, 10);
    expect(p).toMatchObject({ source: 'chrome.processes', cpuPct: 250, cpuMachinePct: 25, privateMemory: 1e8, osPid: 77 });
    expect(processFromNative(null, 4)).toBeNull();
  });
});
