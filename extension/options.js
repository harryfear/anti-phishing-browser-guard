const form = document.getElementById("settings-form");
const policyUrlInput = document.getElementById("policy-url");
const managedNote = document.getElementById("managed-note");
const syncNow = document.getElementById("sync-now");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const policyUrl = policyUrlInput.value.trim();
  await chrome.runtime.sendMessage({ type: "SET_POLICY_URL", policyUrl });
  await refreshStatus();
});

syncNow.addEventListener("click", async () => {
  syncNow.disabled = true;
  try {
    await chrome.runtime.sendMessage({ type: "SYNC_POLICY" });
    await refreshStatus();
  } finally {
    syncNow.disabled = false;
  }
});

refreshStatus();

async function refreshStatus() {
  const response = await chrome.runtime.sendMessage({ type: "GET_STATUS" });
  if (!response || !response.ok) return;

  const { status } = response;
  policyUrlInput.value = status.policyUrl || "";
  policyUrlInput.disabled = status.policyUrlManaged;
  managedNote.hidden = !status.policyUrlManaged;

  document.getElementById("policy-id").textContent = status.policy.policyId || "-";
  document.getElementById("policy-version").textContent = String(status.policy.version || "-");
  document.getElementById("last-sync").textContent = status.lastSyncAt || "Never";
  document.getElementById("last-error").textContent = status.lastSyncError || "None";
}
