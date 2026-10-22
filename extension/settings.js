// Settings shared by the background worker and the settings page.
const SETTINGS_KEY = 'jacktrap_settings';
const SAMPLE_MINUTE_CHOICES = [1, 5, 10, 15];
const DEEP_CPU_CHOICES = [0, 30, 60, 90]; // 0 = always

const DEFAULT_SETTINGS = {
  layer1Enabled: true,
  fetchExternal: true,     // read external script files, not just inline code
  deepScanCpu: 30,         // ...but only when system CPU is at least this %
  sampleMinutes: 5,        // how often the background checks system CPU
  disabledKeywords: [],
  customSignatures: []
};

// Always returns a valid settings object, whatever was stored.
function normalizeSettings(raw) {
  const s = Object.assign({}, DEFAULT_SETTINGS, raw && typeof raw === 'object' ? raw : {});
  s.layer1Enabled = s.layer1Enabled !== false;
  s.fetchExternal = s.fetchExternal !== false;
  s.sampleMinutes = SAMPLE_MINUTE_CHOICES.includes(Number(s.sampleMinutes)) ? Number(s.sampleMinutes) : DEFAULT_SETTINGS.sampleMinutes;
  s.deepScanCpu = DEEP_CPU_CHOICES.includes(Number(s.deepScanCpu)) ? Number(s.deepScanCpu) : DEFAULT_SETTINGS.deepScanCpu;
  s.disabledKeywords = Array.isArray(s.disabledKeywords) ? s.disabledKeywords.filter((k) => typeof k === 'string').slice(0, 100) : [];
  s.customSignatures = Array.isArray(s.customSignatures) ? s.customSignatures.slice(0, 30) : [];
  return s;
}

async function loadSettings() {
  const store = await chrome.storage.local.get(SETTINGS_KEY);
  return normalizeSettings(store[SETTINGS_KEY]);
}

async function saveSettings(patch) {
  const next = normalizeSettings(Object.assign({}, await loadSettings(), patch));
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

if (typeof module !== 'undefined') {
  module.exports = { DEFAULT_SETTINGS, SAMPLE_MINUTE_CHOICES, DEEP_CPU_CHOICES, normalizeSettings };
}
