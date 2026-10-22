const { normalizeSettings, DEFAULT_SETTINGS } = require('../extension/settings.js');

describe('normalizeSettings', () => {
  test('nothing stored gives the defaults', () => {
    expect(normalizeSettings(undefined)).toEqual(DEFAULT_SETTINGS);
    expect(normalizeSettings(null)).toEqual(DEFAULT_SETTINGS);
    expect(normalizeSettings('junk')).toEqual(DEFAULT_SETTINGS);
  });
  test('the default check interval is 5 minutes', () => {
    expect(DEFAULT_SETTINGS.sampleMinutes).toBe(5);
  });
  test('values outside the allowed choices fall back to the default', () => {
    const s = normalizeSettings({ sampleMinutes: 2, deepScanCpu: 55 });
    expect(s.sampleMinutes).toBe(5);
    expect(s.deepScanCpu).toBe(30);
  });
  test('allowed choices are kept (also when stored as text)', () => {
    const s = normalizeSettings({ sampleMinutes: '10', deepScanCpu: 0 });
    expect(s.sampleMinutes).toBe(10);
    expect(s.deepScanCpu).toBe(0);
  });
  test('switches stay on unless set to false', () => {
    expect(normalizeSettings({ layer1Enabled: false }).layer1Enabled).toBe(false);
    expect(normalizeSettings({ layer1Enabled: 'no' }).layer1Enabled).toBe(true);
  });
  test('lists must be lists', () => {
    const s = normalizeSettings({ disabledKeywords: 'x', customSignatures: 7 });
    expect(s.disabledKeywords).toEqual([]);
    expect(s.customSignatures).toEqual([]);
  });
});
