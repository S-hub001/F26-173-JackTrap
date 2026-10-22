function scoreColor(score) {
  if (score >= 60) return "#D32F2F";
  if (score >= 30) return "#F9A825";
  return "#4CAF50";
}

function fmtBytes(n) {
  if (!n) return "0";
  const mb = n / (1024 * 1024);
  return mb.toFixed(1) + " MB";
}

// Live-sampled while the popup is open (fresher than waiting on the
// background worker's 1-minute alarm). Needs two chrome.system.cpu.getInfo()
// readings to compute a percent, so the first refresh after opening shows
// "—" and fills in on the next tick.
let lastPopupCpuSample = null;

async function sampleSystemCpuPercent() {
  try {
    const info = await chrome.system.cpu.getInfo();
    const processors = info.processors.map(p => ({ ...p.usage }));
    let percent = null;
    if (lastPopupCpuSample && lastPopupCpuSample.length === processors.length) {
      let used = 0, total = 0;
      processors.forEach((p, i) => {
        const prev = lastPopupCpuSample[i];
        const dTotal = p.total - prev.total;
        const dIdle = p.idle - prev.idle;
        if (dTotal > 0) { used += (dTotal - dIdle); total += dTotal; }
      });
      percent = total > 0 ? Math.round((used / total) * 100) : null;
    }
    lastPopupCpuSample = processors;
    return percent;
  } catch (e) {
    return null;
  }
}

async function refreshSystemUsage() {
  const cpuEl = document.getElementById("sysCpu");
  const percent = await sampleSystemCpuPercent();
  cpuEl.textContent = percent == null ? "—" : `${percent}%`;
  cpuEl.style.color = percent == null ? "" : scoreColor(percent >= 60 ? 60 : percent >= 30 ? 30 : 0);

  const memEl = document.getElementById("sysMem");
  try {
    const memInfo = await chrome.system.memory.getInfo();
    const used = memInfo.capacity - memInfo.availableCapacity;
    memEl.textContent = `${fmtBytes(used)} / ${fmtBytes(memInfo.capacity)}`;
  } catch (e) {
    memEl.textContent = "—";
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function renderState(state) {
  document.getElementById("pageHost").textContent = state?.hostname || "(no data yet — reload the page)";
  const score = state?.score || 0;
  const badge = document.getElementById("scoreBadge");
  badge.textContent = score;
  badge.style.background = scoreColor(score);

  const t = state?.telemetry || {};
  document.getElementById("wasmCount").textContent = t.wasmInstantiations || 0;
  document.getElementById("workerCount").textContent = t.workersCreated || 0;
  document.getElementById("susWorkers").textContent = (t.suspiciousWorkerNames || []).length;
  document.getElementById("susWs").textContent = (t.websockets || []).filter(w => w.suspicious).length;
  document.getElementById("longTasks").textContent = Math.round(t.longTaskTotalMs || 0);

  const hostList = document.getElementById("hostList");
  const hosts = Object.entries(state?.requestsByHost || {});
  if (hosts.length === 0) {
    hostList.innerHTML = '<div class="empty">No requests captured yet.</div>';
  } else {
    hostList.innerHTML = hosts
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 25)
      .map(([host, rec]) => `
        <div class="host-item">
          <span>${host}</span>
          <span class="muted">${rec.count} req · ports ${rec.ports.join(",")}</span>
        </div>`)
      .join("");
  }

  const susList = document.getElementById("suspiciousList");
  const sus = state?.suspiciousConnections || [];
  susList.innerHTML = sus.length
    ? sus.map(c => `<div class="row"><span class="flag">${c.host}:${c.port}</span><span class="muted">${c.reason}</span></div>`).join("")
    : '<div class="empty">None detected.</div>';
}

async function refresh() {
  const tab = await getActiveTab();
  if (!tab) return;
  chrome.runtime.sendMessage({ type: "GET_STATE", tabId: tab.id }, (resp) => {
    renderState(resp?.state);
  });
  return tab;
}

function renderVtStats(stats) {
  if (!stats) return "";
  const mal = stats.malicious || 0, sus = stats.suspicious || 0, harmless = stats.harmless || 0, undet = stats.undetected || 0;
  const cls = mal > 0 ? "flag" : (sus > 0 ? "flag" : "");
  return `<span class="${cls}">malicious: ${mal}</span><span>suspicious: ${sus}</span><span>harmless: ${harmless}</span><span>undetected: ${undet}</span>`;
}

document.getElementById("vtScanBtn").addEventListener("click", async () => {
  const btn = document.getElementById("vtScanBtn");
  const resultsEl = document.getElementById("vtResults");
  btn.disabled = true;
  btn.textContent = "Scanning (rate-limited, may take a bit)...";
  resultsEl.innerHTML = "";

  const tab = await getActiveTab();
  chrome.runtime.sendMessage({ type: "SCAN_VT", tabId: tab.id }, (resp) => {
    btn.disabled = false;
    btn.textContent = "Check top hosts / IPs with VirusTotal";

    if (!resp || resp.error === "no_state") {
      resultsEl.innerHTML = '<div class="empty">No data for this tab yet.</div>';
      return;
    }
    const { domainResults = [], ipResults = [] } = resp;
    const noKey = [...domainResults, ...ipResults].some(r => r?.error === "no_api_key");
    if (noKey) {
      resultsEl.innerHTML = '<div class="empty">No VirusTotal API key set. Add one on the <a href="#" id="openOptions">options page</a>.</div>';
      document.getElementById("openOptions")?.addEventListener("click", (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
      });
      return;
    }

    const rows = [...domainResults, ...ipResults].map(r => {
      if (!r) return "";
      if (r.error) return `<div class="vt-item">${r.indicator || ""} — lookup error (${r.error})</div>`;
      if (r.notFound) return `<div class="vt-item">${r.indicator} — not in VirusTotal dataset</div>`;
      return `<div class="vt-item"><strong>${r.indicator}</strong> (${r.type})<br/><span class="vt-stats">${renderVtStats(r.stats)}</span></div>`;
    }).join("");
    resultsEl.innerHTML = rows || '<div class="empty">No hosts to check.</div>';
  });
});

document.getElementById("openDashboardBtn").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

refresh();
refreshSystemUsage();
setInterval(refresh, 3000);
setInterval(refreshSystemUsage, 3000);
