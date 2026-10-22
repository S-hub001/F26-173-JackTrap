const fs = require('fs');
const path = require('path');
const L1 = require('../extension/layer1.js');
const SIGNATURES = require('../extension/signatures.js');

const { scanSources, summarize, mergeHitMaps, activeSignatures, sanitizeCustomSignatures,
  layer1Points, isFetchableUrl, isThirdParty, emptyLayer1 } = L1;

const inline = (text, label = 'inline script 1') => [{ label, kind: 'inline', text }];
const scan = (text) => summarize(scanSources(inline(text), SIGNATURES));

function pageScripts(name) {
  const html = fs.readFileSync(path.join(__dirname, '..', 'test-pages', name), 'utf8');
  const out = [];
  html.replace(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi, (_m, code) => out.push(code));
  return out.join('\n');
}

describe('the ten words from the supervisor', () => {
  test.each([
    ['CoinHive.Anonymous("key")', 'coinhive'],
    ['WebAssembly.instantiate(buf)', 'webassembly.instantiate'],
    ['algo: "CryptoNight"', 'cryptonight'],
    ['miner.start();', 'miner.start('],
    ['./xmrig --donate-level 1', 'xmrig'],
    ['sendPayout(wallet)', 'wallet'],
    ['the stratum protocol', 'stratum'],
    ['current hashrate: 12', 'hashrate'],
    ['new Worker("w.js")', 'worker'],
    ['join the pool', 'pool']
  ])('finds %s', (text, keyword) => {
    const result = scanSources(inline(text), SIGNATURES);
    expect(Object.keys(result)).toContain(keyword);
  });
});

describe('matching rules', () => {
  test('is not case sensitive', () => {
    expect(scan('COINHIVE').level).toBe('strong');
  });
  test('whole words only: coworker is not worker, carpool is not pool', () => {
    expect(scan('my coworker took a carpool').hits).toEqual([]);
  });
  test('instantiateStreaming is its own word, not instantiate', () => {
    const keys = Object.keys(scanSources(inline('WebAssembly.instantiateStreaming(r)'), SIGNATURES));
    expect(keys).toContain('webassembly.instantiatestreaming');
    expect(keys).not.toContain('webassembly.instantiate');
  });
  test('script file names count (url source)', () => {
    const map = scanSources([{ label: 'https://x.com/coinhive.min.js', kind: 'url', text: 'https://x.com/coinhive.min.js' }], SIGNATURES);
    expect(map.coinhive.where[0].kind).toBe('url');
  });
  test('empty, null and undefined input do not crash', () => {
    expect(scan('').level).toBe('clean');
    expect(scan(null).level).toBe('clean');
    expect(scan(undefined).level).toBe('clean');
    expect(summarize(scanSources([{ label: 'x', kind: 'inline' }], SIGNATURES)).level).toBe('clean');
  });
  test('a huge script does not crash and only the first 400000 characters are read', () => {
    const big = 'a'.repeat(1000000) + ' coinhive';
    expect(() => scan(big)).not.toThrow();
    expect(scan(big).level).toBe('clean');
  });
  test('snippet has no control characters and stays short', () => {
    const map = scanSources(inline('x\n\n\u0007coinhive ' + 'y'.repeat(500)), SIGNATURES);
    const snippet = map.coinhive.where[0].snippet;
    expect(snippet).not.toMatch(/[\u0000-\u001f]/);
    expect(snippet.length).toBeLessThanOrEqual(90);
  });
});

describe('levels and points', () => {
  test('weak words alone do not count', () => {
    const r = scan('new Worker("a.js"); wallet; pool');
    expect(r.weakCount).toBe(3);
    expect(r.level).toBe('clean');
    expect(r.points).toBe(0);
  });
  test('one possible sign gives a small nudge', () => {
    const r = scan('WebAssembly.instantiate(x)');
    expect(r.level).toBe('possible');
    expect(r.points).toBe(4);
  });
  test('possible signs never add more than 12 points', () => {
    const r = scan('webassembly.instantiate webassembly.compile stratum hashrate worker pool');
    expect(r.level).toBe('possible');
    expect(r.points).toBeLessThanOrEqual(12);
  });
  test('one strong sign is 22 points (15 + 7)', () => {
    expect(scan('coinhive').points).toBe(22);
  });
  test('weak words add at most 2 once a strong word exists', () => {
    const r = scan('xmrig worker wallet pool');
    expect(r.weakCounted).toBe(2);
    expect(r.points).toBe(15 + 7 + 2);
  });
  test('points never go above 50', () => {
    expect(layer1Points('strong', 20, 20, 2)).toBe(50);
  });
});

describe('merging results from more scripts', () => {
  test('keeps both keywords and does not repeat the same place', () => {
    const a = scanSources(inline('coinhive', 'inline script 1'), SIGNATURES);
    const b = scanSources(inline('coinhive xmrig', 'inline script 1'), SIGNATURES);
    mergeHitMaps(a, b);
    expect(Object.keys(a).sort()).toEqual(['coinhive', 'xmrig']);
    expect(a.coinhive.where.length).toBe(1);
  });
  test('remembers at most 3 places per word', () => {
    const map = {};
    for (let i = 1; i <= 6; i++) mergeHitMaps(map, scanSources(inline('coinhive', 'script ' + i), SIGNATURES));
    expect(map.coinhive.where.length).toBe(3);
  });
});

describe('the user signature list', () => {
  test('a disabled word is skipped', () => {
    const list = activeSignatures(SIGNATURES, { disabledKeywords: ['coinhive'] });
    expect(list.some((s) => s.keyword === 'coinhive')).toBe(false);
    expect(summarize(scanSources(inline('coinhive'), list)).level).toBe('clean');
  });
  test('a custom word is used', () => {
    const list = activeSignatures(SIGNATURES, { customSignatures: [{ keyword: 'WebMinePool', weight: 4 }] });
    expect(summarize(scanSources(inline('webminepool'), list)).level).toBe('strong');
  });
  test('bad custom words are dropped', () => {
    const clean = sanitizeCustomSignatures([
      { keyword: 'ab', weight: 4 }, { keyword: 5 }, null, { keyword: 'x'.repeat(61) },
      { keyword: 'good-one', weight: 9 }, { keyword: 'GOOD-ONE', weight: 4 }
    ]);
    expect(clean).toEqual([{ keyword: 'good-one', weight: 2, custom: true, note: 'Added by you.' }]);
  });
});

describe('helpers', () => {
  test('isFetchableUrl allows only http and https', () => {
    expect(isFetchableUrl('https://a.com/x.js')).toBe(true);
    expect(isFetchableUrl('data:text/javascript,1')).toBe(false);
    expect(isFetchableUrl('chrome-extension://abc/x.js')).toBe(false);
    expect(isFetchableUrl('not a url')).toBe(false);
  });
  test('isThirdParty compares host names', () => {
    expect(isThirdParty('https://cdn.other.com/a.js', 'site.com')).toBe(true);
    expect(isThirdParty('https://site.com/a.js', 'site.com')).toBe(false);
  });
  test('emptyLayer1 gives a fresh object every time', () => {
    const a = emptyLayer1();
    a.hitMap.x = 1;
    expect(emptyLayer1().hitMap).toEqual({});
  });
});

describe('on the test pages', () => {
  test('normal.html is clean', () => {
    expect(scan(pageScripts('normal.html')).level).toBe('clean');
  });
  test('fake-miner.html has strong signs', () => {
    const r = scan(pageScripts('fake-miner.html'));
    expect(r.level).toBe('strong');
    expect(r.strongCount).toBeGreaterThanOrEqual(4);
  });
  test('external.html looks clean until its script file is read', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'test-pages', 'external.html'), 'utf8');
    expect(scan(html).level).toBe('clean');
    const file = fs.readFileSync(path.join(__dirname, '..', 'test-pages', 'assets', 'app.js'), 'utf8');
    expect(scan(file).level).toBe('strong');
  });
  test('KNOWN LIMIT: obfuscated.html slips through', () => {
    expect(scan(pageScripts('obfuscated.html')).level).toBe('clean');
  });
});
