async function load() {
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  document.getElementById("apiKey").value = vtApiKey || "";
}

document.getElementById("save").addEventListener("click", async () => {
  const key = document.getElementById("apiKey").value.trim();
  await chrome.storage.local.set({ vtApiKey: key });
  const status = document.getElementById("status");
  status.textContent = "Saved.";
  setTimeout(() => (status.textContent = ""), 2000);
});

load();
