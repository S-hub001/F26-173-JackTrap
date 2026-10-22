// Layer 1: static JavaScript scanner (signature based).
// Everything here is a pure function (text in, result out) with no Chrome
// APIs, so it can be unit tested in Node and reused by the background worker.

const LAYER1_LIMITS = {
  maxChars: 400000,        // never read more than this much text from one source
  maxExternalBytes: 300000, // download at most this much of one script file
  maxExternalFiles: 12,    // script files read per scan run
  maxExternalPerPage: 40,  // script files read per page, in total
  maxUrlsTracked: 100,     // script addresses remembered per page
  fetchTimeoutMs: 6000,
  snippetRadius: 24,
  maxWhere: 3              // places remembered per found keyword
};

// ---------- matching ----------
const patternCache = new Map();

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Whole-word matching: "worker" matches "new Worker(" but not "coworker".
function buildPattern(keyword) {
  if (patternCache.has(keyword)) return patternCache.get(keyword);
  const start = /^\w/.test(keyword) ? '\\b' : '';
  const end = /\w$/.test(keyword) ? '\\b' : '';
  const pattern = new RegExp(start + escapeRegex(keyword) + end, 'i');
  patternCache.set(keyword, pattern);
  return pattern;
}

function levelOfWeight(weight) {
  if (weight >= 4) return 'strong';
  if (weight >= 2) return 'possible';
  return 'weak';
}

// Short, safe-to-display piece of text around a match.
function makeSnippet(text, index, length) {
  const r = LAYER1_LIMITS.snippetRadius;
  const raw = text.slice(Math.max(0, index - r), index + length + r);
  return raw.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 90);
}

// ---------- signature list (built-in + the user's changes) ----------
function sanitizeCustomSignatures(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  const seen = new Set();
  for (const item of list) {
    if (!item || typeof item.keyword !== 'string') continue;
    const keyword = item.keyword.trim().toLowerCase();
    if (keyword.length < 3 || keyword.length > 60 || seen.has(keyword)) continue;
    const weight = [1, 2, 4].includes(Number(item.weight)) ? Number(item.weight) : 2;
    seen.add(keyword);
    out.push({ keyword, weight, custom: true, note: 'Added by you.' });
    if (out.length >= 30) break;
  }
  return out;
}

function activeSignatures(base, settings) {
  const off = new Set((settings && settings.disabledKeywords) || []);
  const custom = sanitizeCustomSignatures(settings && settings.customSignatures);
  return base.concat(custom).filter((sig) => !off.has(sig.keyword));
}

// ---------- scanning ----------
// source = { label, kind: 'inline' | 'url' | 'external', text }
function scanSource(source, signatures) {
  const text = String((source && source.text) || '').slice(0, LAYER1_LIMITS.maxChars);
  const found = [];
  if (!text) return found;
  for (const sig of signatures) {
    const match = buildPattern(sig.keyword).exec(text);
    if (match) {
      found.push({
        keyword: sig.keyword,
        weight: sig.weight,
        label: source.label,
        kind: source.kind,
        snippet: makeSnippet(text, match.index, match[0].length)
      });
    }
  }
  return found;
}

// Returns { keyword: { keyword, weight, where: [{label, kind, snippet}] } }
function scanSources(sources, signatures) {
  const map = {};
  for (const source of sources) {
    for (const hit of scanSource(source, signatures)) {
      if (!map[hit.keyword]) map[hit.keyword] = { keyword: hit.keyword, weight: hit.weight, where: [] };
      const entry = map[hit.keyword];
      if (entry.where.length < LAYER1_LIMITS.maxWhere) {
        entry.where.push({ label: hit.label, kind: hit.kind, snippet: hit.snippet });
      }
    }
  }
  return map;
}

// Adds the hits in "extra" into "target" (used when more scripts arrive).
function mergeHitMaps(target, extra) {
  for (const [keyword, entry] of Object.entries(extra)) {
    if (!target[keyword]) {
      target[keyword] = { keyword, weight: entry.weight, where: entry.where.slice() };
      continue;
    }
    for (const place of entry.where) {
      const dupe = target[keyword].where.some((w) => w.label === place.label && w.kind === place.kind);
      if (!dupe && target[keyword].where.length < LAYER1_LIMITS.maxWhere) target[keyword].where.push(place);
    }
  }
  return target;
}

// ---------- scoring ----------
// Points added to the 0-100 suspicion score.
//  - any strong sign: 15 base + 7 per strong + 3 per possible + weak (max 2)
//  - only possible signs: small nudge, never more than 12
//  - weak words alone: 0
function layer1Points(level, strongN, possibleN, weakCounted) {
  if (level === 'strong') return Math.min(50, 15 + 7 * strongN + 3 * possibleN + weakCounted);
  if (level === 'possible') return Math.min(12, 4 * possibleN + weakCounted);
  return 0;
}

function summarize(hitMap) {
  const hits = Object.values(hitMap).sort((a, b) => b.weight - a.weight || a.keyword.localeCompare(b.keyword));
  const strong = hits.filter((h) => levelOfWeight(h.weight) === 'strong');
  const possible = hits.filter((h) => levelOfWeight(h.weight) === 'possible');
  const weak = hits.filter((h) => levelOfWeight(h.weight) === 'weak');

  const level = strong.length ? 'strong' : possible.length ? 'possible' : 'clean';
  const weakCounted = level === 'clean' ? 0 : Math.min(2, weak.length);

  return {
    hits,
    level,
    strongCount: strong.length,
    possibleCount: possible.length,
    weakCount: weak.length,
    weakCounted,
    points: layer1Points(level, strong.length, possible.length, weakCounted)
  };
}

function emptyLayer1() {
  return {
    disabled: false,
    level: 'clean',
    points: 0,
    strongCount: 0,
    possibleCount: 0,
    weakCount: 0,
    weakCounted: 0,
    hits: [],
    hitMap: {},
    inlineScanned: 0,
    urlsSeen: {},
    externalQueue: [],
    externalDone: 0,
    externalFailed: 0,
    externalTotal: 0,
    scannedAt: null,
    lastLoggedLevel: 'clean'
  };
}

// ---------- small helpers for script addresses ----------
function isFetchableUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch (e) {
    return false;
  }
}

function isThirdParty(url, pageHost) {
  try {
    return new URL(url).hostname !== pageHost;
  } catch (e) {
    return false;
  }
}

if (typeof module !== 'undefined') {
  module.exports = {
    LAYER1_LIMITS, buildPattern, levelOfWeight, sanitizeCustomSignatures, activeSignatures,
    scanSource, scanSources, mergeHitMaps, layer1Points, summarize, emptyLayer1,
    isFetchableUrl, isThirdParty
  };
}
