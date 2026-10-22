/* global SIGNATURES, DEFAULT_SETTINGS, loadSettings, saveSettings */
// Settings page. Changes save as soon as they are made.

const $ = (id) => document.getElementById(id);

function h(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

let toastTimer = null;
function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 1600);
}

let settings = null;

async function update(patch, message) {
  settings = await saveSettings(patch);
  toast(message || "Saved");
  renderSignatures();
}

// ---------- signature list ----------
const GROUPS = [
  { title: "Strong", hint: "worth the most points", test: (s) => s.weight >= 4 },
  { title: "Possible", hint: "a small nudge", test: (s) => s.weight >= 2 && s.weight < 4 },
  { title: "Weak", hint: "only counted next to a stronger word", test: (s) => s.weight < 2 }
];

function sigRow(sig) {
  const off = settings.disabledKeywords.includes(sig.keyword);
  const input = h("input", {
    type: "checkbox", role: "switch", "aria-label": "Use " + sig.keyword,
    onchange: (e) => {
      const set = new Set(settings.disabledKeywords);
      if (e.target.checked) set.delete(sig.keyword); else set.add(sig.keyword);
      update({ disabledKeywords: [...set] });
    }
  });
  input.checked = !off;
  return h("div", { class: "sig" },
    h("span", { class: "switch" }, input, h("span")),
    h("span", null, h("span", { class: "kw" }, sig.keyword)),
    h("span", { class: "note" }, sig.custom ? h("span", { class: "own" }, "Yours") : null, sig.note || ""),
    sig.custom
      ? h("button", { class: "linkbtn", type: "button", onclick: () => {
          update({ customSignatures: settings.customSignatures.filter((c) => c.keyword !== sig.keyword) }, "Removed");
        } }, "Remove")
      : h("span")
  );
}

function renderSignatures() {
  const custom = settings.customSignatures
    .filter((c) => c && typeof c.keyword === "string")
    .map((c) => ({ keyword: c.keyword, weight: Number(c.weight) || 2, custom: true, note: "" }));
  const all = SIGNATURES.concat(custom);
  $("sigGroups").replaceChildren(...GROUPS.map((group) => {
    const rows = all.filter(group.test);
    return h("div", { class: "sig-group" },
      h("h3", null, group.title, h("span", null, group.hint)),
      rows.length ? rows.map(sigRow) : h("p", { class: "help" }, "Nothing here.")
    );
  }));
}

$("addForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const keyword = $("newKeyword").value.trim().toLowerCase();
  const weight = Number($("newWeight").value);
  const error = $("addError");
  const taken = SIGNATURES.concat(settings.customSignatures).some((s) => s.keyword === keyword);
  if (keyword.length < 3) { error.textContent = "Use at least 3 characters so the word doesn’t match everything."; return; }
  if (taken) { error.textContent = "That word is already in the list."; return; }
  if (settings.customSignatures.length >= 30) { error.textContent = "You can add up to 30 words. Remove one first."; return; }
  error.textContent = "";
  $("newKeyword").value = "";
  await update({ customSignatures: settings.customSignatures.concat([{ keyword, weight }]) }, "Word added");
});

// ---------- simple controls ----------
function bindControls() {
  $("sampleMinutes").value = String(settings.sampleMinutes);
  $("deepScanCpu").value = String(settings.deepScanCpu);
  $("layer1Enabled").checked = settings.layer1Enabled;
  $("fetchExternal").checked = settings.fetchExternal;

  $("sampleMinutes").addEventListener("change", (e) => update({ sampleMinutes: Number(e.target.value) }));
  $("deepScanCpu").addEventListener("change", (e) => update({ deepScanCpu: Number(e.target.value) }));
  $("layer1Enabled").addEventListener("change", (e) => update({ layer1Enabled: e.target.checked }));
  $("fetchExternal").addEventListener("change", (e) => update({ fetchExternal: e.target.checked }));

  // Set the checkbox state when the options page loads
  $("layer2Precise").checked = settings.layer2Precise;

  $("layer2Precise").addEventListener("change", (e) => {
    const box = e.target;
    
    // The permission is already granted via manifest.json.
    // Simply update the user's setting preference.
    update({ layer2Precise: box.checked });
    
    if (box.checked) {
      toast("Precise per-tab measurement enabled");
    }
  });
}

// ---------- VirusTotal key ----------
$("showKey").addEventListener("click", () => {
  const input = $("apiKey");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  $("showKey").textContent = showing ? "Show" : "Hide";
  $("showKey").setAttribute("aria-pressed", String(!showing));
});

$("saveKey").addEventListener("click", async () => {
  await chrome.storage.local.set({ vtApiKey: $("apiKey").value.trim() });
  toast("Key saved");
});

// ---------- data ----------
$("clearLog").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_EVENT_LOG" }, () => toast("Event log cleared"));
});

$("clearVt").addEventListener("click", async () => {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith("vtcache_"));
  await chrome.storage.local.remove(keys);
  toast("Saved results cleared");
});

$("resetSettings").addEventListener("click", async () => {
  await chrome.storage.local.set({ jacktrap_settings: DEFAULT_SETTINGS });
  settings = await loadSettings();
  bindValues();
  renderSignatures();
  toast("Settings reset");
});

function bindValues() {
  $("sampleMinutes").value = String(settings.sampleMinutes);
  $("deepScanCpu").value = String(settings.deepScanCpu);
  $("layer1Enabled").checked = settings.layer1Enabled;
  $("fetchExternal").checked = settings.fetchExternal;
  $("layer2Precise").checked = settings.layer2Precise;
}

(async function start() {
  settings = await loadSettings();
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  $("apiKey").value = vtApiKey || "";
  bindControls();
  renderSignatures();
})();
