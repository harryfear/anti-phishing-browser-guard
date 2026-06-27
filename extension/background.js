importScripts("brand.js", "shared.js");

const STORAGE_KEYS = {
  policy: "policy",
  policyUrl: "policyUrl",
  lastSyncAt: "lastSyncAt",
  lastSyncError: "lastSyncError",
  identityHints: "identityHints"
};

const DEFAULT_POLICY_URL = "";
const DEFAULT_ALARM_NAME = "policy-sync";
const FRAME_EVALUATION_TTL_MS = 30 * 1000;
const DNR_RULE_ID_BASE = 1000;
const DNR_RULE_LIMIT = 100;
const DNR_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "other"
];
const frameEvaluationsByTab = new Map();

chrome.runtime.onInstalled.addListener(async () => {
  const current = await storageGet([STORAGE_KEYS.policy, STORAGE_KEYS.policyUrl]);
  if (!current[STORAGE_KEYS.policy]) {
    await storageSet({ [STORAGE_KEYS.policy]: PhishGuard.DEFAULT_POLICY });
  }
  if (current[STORAGE_KEYS.policyUrl] === undefined) {
    await storageSet({ [STORAGE_KEYS.policyUrl]: DEFAULT_POLICY_URL });
  }
  await chrome.alarms.create(DEFAULT_ALARM_NAME, { periodInMinutes: 60 });
  await syncPolicy();
  await syncDenyHostRules(await getPolicy());
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === DEFAULT_ALARM_NAME) {
    syncPolicy();
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true;
});

async function handleMessage(message, sender) {
  switch (message && message.type) {
    case "GET_POLICY":
      return { ok: true, policy: await getPolicy() };
    case "GET_STATUS":
      return { ok: true, status: await getStatus() };
    case "SET_POLICY_URL":
      await storageSet({ [STORAGE_KEYS.policyUrl]: String(message.policyUrl || "").trim() });
      return { ok: true, status: await getStatus() };
    case "SYNC_POLICY":
      await syncPolicy({ force: true });
      return { ok: true, status: await getStatus() };
    case "GET_IDENTITY_HINT":
      return { ok: true, hint: await getIdentityHint(message.siteKey, sender) };
    case "RECORD_IDENTITY_HINT":
      return { ok: true, hint: await recordIdentityHint(message.hint, sender) };
    case "REPORT_FRAME_EVALUATION":
      await recordFrameEvaluation(message.evaluation, sender);
      return { ok: true };
    case "GET_FRAME_EVALUATIONS":
      return { ok: true, evaluations: getFrameEvaluations(sender) };
    case "REPORT_EVENT":
      await reportEvent(message.event, sender);
      return { ok: true };
    case "CAPTURE_SCREENSHOT":
      return { ok: true, ...(await captureAndDownload(sender)) };
    default:
      return { ok: false, error: "Unknown message type" };
  }
}

async function captureAndDownload(sender) {
  try {
    const windowId = sender && sender.tab ? sender.tab.windowId : undefined;
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: "png" });
    const host = (hostFromSender(sender) || "page").replace(/[^a-z0-9.-]/gi, "_");
    const stamp = Math.floor(Date.now() / 1000);
    await chrome.downloads.download({
      url: dataUrl,
      filename: `phishing-report-${host}-${stamp}.png`,
      saveAs: false
    });
    return { saved: true };
  } catch (error) {
    return { saved: false, error: error.message };
  }
}

async function getPolicy() {
  const values = await storageGet([STORAGE_KEYS.policy]);
  return PhishGuard.normalizePolicy(values[STORAGE_KEYS.policy]);
}

async function getPolicyUrl() {
  const managed = await readManagedPolicyUrl();
  if (managed) return managed;

  const values = await storageGet([STORAGE_KEYS.policyUrl]);
  return String(values[STORAGE_KEYS.policyUrl] || "").trim();
}

async function readManagedPolicyUrl() {
  try {
    const managed = await chrome.storage.managed.get(["policyUrl"]);
    return String(managed.policyUrl || "").trim();
  } catch (_) {
    return "";
  }
}

async function getStatus() {
  const values = await storageGet([
    STORAGE_KEYS.policy,
    STORAGE_KEYS.policyUrl,
    STORAGE_KEYS.lastSyncAt,
    STORAGE_KEYS.lastSyncError
  ]);
  const managedPolicyUrl = await readManagedPolicyUrl();
  const policy = PhishGuard.normalizePolicy(values[STORAGE_KEYS.policy]);

  return {
    policy,
    policyUrl: managedPolicyUrl || values[STORAGE_KEYS.policyUrl] || "",
    policyUrlManaged: Boolean(managedPolicyUrl),
    lastSyncAt: values[STORAGE_KEYS.lastSyncAt] || "",
    lastSyncError: values[STORAGE_KEYS.lastSyncError] || ""
  };
}

async function syncPolicy(options = {}) {
  const policyUrl = await getPolicyUrl();
  if (!policyUrl) return;

  const current = await getStatus();
  const refreshMinutes = Number(current.policy.refreshMinutes || 240);
  const lastSyncAt = Date.parse(current.lastSyncAt || "");
  const syncDue = !lastSyncAt || Date.now() - lastSyncAt >= refreshMinutes * 60 * 1000;
  if (!options.force && !syncDue) return;

  try {
    const response = await fetch(policyUrl, {
      cache: "no-store",
      credentials: "omit",
      headers: { accept: "application/json" }
    });
    if (!response.ok) throw new Error(`Policy fetch failed: HTTP ${response.status}`);

    const policy = sanitizeRuntimePolicy(await response.json(), current.policy);
    validateRuntimePolicy(policy);

    await storageSet({
      [STORAGE_KEYS.policy]: policy,
      [STORAGE_KEYS.lastSyncAt]: new Date().toISOString(),
      [STORAGE_KEYS.lastSyncError]: ""
    });
    await syncDenyHostRules(policy);
  } catch (error) {
    await storageSet({
      [STORAGE_KEYS.lastSyncError]: error.message
    });
  }
}

function sanitizeRuntimePolicy(candidate, currentPolicy) {
  const policy = PhishGuard.normalizePolicy(candidate);
  const current = PhishGuard.normalizePolicy(currentPolicy);

  if (!Number.isInteger(policy.version) || policy.version < 1) {
    throw new Error("Policy version must be a positive integer");
  }
  if (Number.isInteger(current.version) && policy.version < current.version) {
    throw new Error("Policy version rollback rejected");
  }

  policy.refreshMinutes = clampInteger(policy.refreshMinutes, 240, 15, 1440);
  const warnThreshold = clampInteger(policy.actions.warnThreshold, 45, 1, 99);
  policy.actions = {
    warnThreshold,
    blockThreshold: clampInteger(policy.actions.blockThreshold, 80, warnThreshold + 1, 100),
    identityChallengeMinutes: clampInteger(policy.actions.identityChallengeMinutes, 5, 1, 60)
  };

  policy.protectedDomains = sanitizeHostList(policy.protectedDomains, {
    path: "protectedDomains",
    wildcard: false,
    min: 1
  });
  policy.protectedEmailDomains = sanitizeHostList(policy.protectedEmailDomains, {
    path: "protectedEmailDomains",
    wildcard: false,
    min: 1
  });
  policy.trustedHosts = sanitizeHostList(policy.trustedHosts, {
    path: "trustedHosts",
    wildcard: true,
    min: 1
  });
  policy.trustedLoginHosts = sanitizeHostList(policy.trustedLoginHosts, {
    path: "trustedLoginHosts",
    wildcard: false,
    min: 1
  });
  policy.denyHosts = sanitizeHostList(policy.denyHosts, {
    path: "denyHosts",
    wildcard: true,
    min: 0
  });
  policy.protectedBrands = sanitizeStringList(policy.protectedBrands, "protectedBrands", 1);

  policy.infoUrl = safeHttpsUrl(policy.infoUrl) || current.infoUrl || "";
  policy.approvedLoginUrl = safeApprovedLoginUrl(policy.approvedLoginUrl, current);
  policy.approvedLoginLabel =
    typeof policy.approvedLoginLabel === "string" && policy.approvedLoginLabel.trim()
      ? policy.approvedLoginLabel.trim().slice(0, 80)
      : "Open approved login";
  policy.reportEndpoint = lockedReportEndpoint(policy.reportEndpoint, current.reportEndpoint);
  policy.reportEmail = safeReportEmail(policy.reportEmail, current.reportEmail);

  return policy;
}

function validateRuntimePolicy(policy) {
  if (!policy || typeof policy !== "object") throw new Error("Policy must be an object");
  if (!Array.isArray(policy.protectedDomains)) throw new Error("Policy protectedDomains must be an array");
  if (!Array.isArray(policy.trustedHosts)) throw new Error("Policy trustedHosts must be an array");
  if (!Array.isArray(policy.trustedLoginHosts)) throw new Error("Policy trustedLoginHosts must be an array");
}

function sanitizeHostList(values, options) {
  if (!Array.isArray(values)) throw new Error(`Policy ${options.path} must be an array`);

  const seen = new Set();
  const result = [];
  for (const rawValue of values) {
    const value = PhishGuard.normalizeHost(rawValue);
    if (!value) continue;
    if (!isValidHostPattern(value, options.wildcard)) {
      throw new Error(`Policy ${options.path} contains invalid host pattern: ${rawValue}`);
    }
    if (!options.wildcard && value.includes("*")) {
      throw new Error(`Policy ${options.path} must not contain wildcard hosts`);
    }
    if (PhishGuard.isKnownPublicSuffix(value.replace(/^\*\./, ""))) {
      throw new Error(`Policy ${options.path} must not contain public suffix host: ${rawValue}`);
    }
    if (PhishGuard.isUnsafeWildcardPattern(value)) {
      throw new Error(`Policy ${options.path} must not wildcard a public suffix: ${rawValue}`);
    }
    if (seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }

  if (result.length < options.min) {
    throw new Error(`Policy ${options.path} must contain at least ${options.min} item(s)`);
  }
  return result;
}

function sanitizeStringList(values, path, min) {
  if (!Array.isArray(values)) throw new Error(`Policy ${path} must be an array`);
  const result = Array.from(
    new Set(
      values
        .filter((value) => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean)
    )
  );
  if (result.length < min) throw new Error(`Policy ${path} must contain at least ${min} item(s)`);
  return result;
}

function isValidHostPattern(value, wildcard) {
  if (value.includes("://") || value.includes("/") || value.includes(":")) return false;
  const pattern = wildcard
    ? /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i
    : /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;
  return pattern.test(value);
}

function safeHttpsUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(String(value).trim());
    return url.protocol === "https:" ? url.href : "";
  } catch (_) {
    return "";
  }
}

function safeApprovedLoginUrl(value, policy) {
  const url = safeHttpsUrl(value);
  if (!url) return "";
  try {
    const parsed = new URL(url);
    const allowedHosts = [
      ...policy.protectedDomains,
      ...policy.trustedLoginHosts,
      ...policy.trustedHosts.filter((host) => !host.startsWith("*."))
    ];
    return PhishGuard.hostInList(parsed.hostname, allowedHosts) ? parsed.href : "";
  } catch (_) {
    return "";
  }
}

function lockedReportEndpoint(candidateValue, currentValue) {
  const candidate = safeHttpsUrl(candidateValue);
  const current = safeHttpsUrl(currentValue);
  if (!candidate || !current) return "";
  try {
    const candidateUrl = new URL(candidate);
    const currentUrl = new URL(current);
    return candidateUrl.origin === currentUrl.origin ? candidate : current;
  } catch (_) {
    return "";
  }
}

function safeReportEmail(value, fallback) {
  const email = String(value || "").trim();
  // A single clean address only: no mailto query injection (?cc=, &bcc=, newlines).
  if (/^[^\s@?&/=,;:]+@[^\s@?&/=,;:]+\.[^\s@?&/=,;:]+$/.test(email)) return email;
  return String(fallback || "").trim();
}

function clampInteger(value, fallback, min, max) {
  const number = Number.isInteger(value) ? value : fallback;
  return Math.min(max, Math.max(min, number));
}

async function syncDenyHostRules(policy) {
  if (!chrome.declarativeNetRequest) return;
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules
      .map((rule) => rule.id)
      .filter((id) => id >= DNR_RULE_ID_BASE && id < DNR_RULE_ID_BASE + DNR_RULE_LIMIT);
    const addRules = (policy.denyHosts || [])
      .slice(0, DNR_RULE_LIMIT)
      .map((pattern, index) => dynamicBlockRule(pattern, DNR_RULE_ID_BASE + index))
      .filter(Boolean);

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
  } catch (_) {
    // Overlay enforcement still applies if dynamic rule installation is unavailable.
  }
}

function dynamicBlockRule(pattern, id) {
  const domain = PhishGuard.normalizeHost(pattern).replace(/^\*\./, "");
  if (!domain || PhishGuard.isKnownPublicSuffix(domain)) return null;
  return {
    id,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: DNR_RESOURCE_TYPES
    }
  };
}

async function getIdentityHint(rawSiteKey, sender) {
  const siteKey = PhishGuard.normalizeHost(rawSiteKey);
  const tabKey = sender?.tab?.id !== undefined ? tabIdentityKey(sender.tab.id) : "";
  if (!siteKey && !tabKey) return null;

  const hints = await getPrunedIdentityHints();
  return hints[siteKey] || hints[tabKey] || null;
}

async function recordIdentityHint(rawHint, sender) {
  const policy = await getPolicy();
  const hostname = PhishGuard.normalizeHost(
    rawHint?.hostname || hostFromSender(sender)
  );
  const siteKey = PhishGuard.normalizeHost(rawHint?.siteKey || PhishGuard.siteKey(hostname));
  if (!siteKey) return null;

  const now = Date.now();
  const ttlMinutes = Number(policy.actions.identityChallengeMinutes || 5);
  const ttlMs = Math.max(1, ttlMinutes) * 60 * 1000;
  const hints = await getPrunedIdentityHints(now);
  const existing = hints[siteKey];

  hints[siteKey] = {
    siteKey,
    hostname,
    reason: "protected-email-entered",
    firstSeenAt: existing?.firstSeenAt || new Date(now).toISOString(),
    lastSeenAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString()
  };

  if (sender?.tab?.id !== undefined) {
    const tabKey = tabIdentityKey(sender.tab.id);
    const existingTab = hints[tabKey];
    hints[tabKey] = {
      siteKey: tabKey,
      hostname,
      reason: "protected-email-entered-tab",
      firstSeenAt: existingTab?.firstSeenAt || new Date(now).toISOString(),
      lastSeenAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString()
    };
  }

  const keys = Object.keys(hints);
  if (keys.length > 50) {
    keys
      .sort((a, b) => Date.parse(hints[a].expiresAt) - Date.parse(hints[b].expiresAt))
      .slice(0, keys.length - 50)
      .forEach((key) => delete hints[key]);
  }

  await storageSet({ [STORAGE_KEYS.identityHints]: hints });
  return hints[siteKey];
}

async function getPrunedIdentityHints(now = Date.now()) {
  const values = await storageGet([STORAGE_KEYS.identityHints]);
  const hints =
    values[STORAGE_KEYS.identityHints] &&
    typeof values[STORAGE_KEYS.identityHints] === "object"
      ? values[STORAGE_KEYS.identityHints]
      : {};

  let changed = false;
  for (const [key, hint] of Object.entries(hints)) {
    if (!hint || Date.parse(hint.expiresAt || "") <= now) {
      delete hints[key];
      changed = true;
    }
  }

  if (changed) await storageSet({ [STORAGE_KEYS.identityHints]: hints });
  return hints;
}

function tabIdentityKey(tabId) {
  return `tab:${tabId}`;
}

async function recordFrameEvaluation(evaluation, sender) {
  if (!sender?.tab?.id || sender.frameId === undefined || sender.frameId === 0) return;

  const tabId = sender.tab.id;
  const frameId = sender.frameId;
  const tabEvaluations = frameEvaluationsByTab.get(tabId) || new Map();

  if (!evaluation || evaluation.action === "allow") {
    tabEvaluations.delete(frameId);
  } else {
    tabEvaluations.set(frameId, {
      action: evaluation.action,
      score: Number(evaluation.score || 0),
      signals: Array.isArray(evaluation.signals) ? evaluation.signals.slice(0, 20) : [],
      hostname: PhishGuard.normalizeHost(evaluation.hostname || hostFromSender(sender)),
      title: String(evaluation.title || "").slice(0, 200),
      frameId,
      expiresAt: Date.now() + FRAME_EVALUATION_TTL_MS
    });
  }

  if (tabEvaluations.size) {
    frameEvaluationsByTab.set(tabId, tabEvaluations);
  } else {
    frameEvaluationsByTab.delete(tabId);
  }

  try {
    await chrome.tabs.sendMessage(tabId, { type: "FRAME_EVALUATION_UPDATED" }, { frameId: 0 });
  } catch (_) {
    // The top frame may not have a content script yet.
  }
}

function getFrameEvaluations(sender) {
  if (!sender?.tab?.id) return [];
  const tabId = sender.tab.id;
  const tabEvaluations = frameEvaluationsByTab.get(tabId);
  if (!tabEvaluations) return [];

  const now = Date.now();
  const result = [];
  for (const [frameId, evaluation] of tabEvaluations.entries()) {
    if (!evaluation || evaluation.expiresAt <= now) {
      tabEvaluations.delete(frameId);
      continue;
    }
    result.push(evaluation);
  }

  if (!tabEvaluations.size) frameEvaluationsByTab.delete(tabId);
  return result;
}

function hostFromSender(sender) {
  try {
    return sender?.tab?.url ? new URL(sender.tab.url).hostname : "";
  } catch (_) {
    return "";
  }
}

async function reportEvent(event, sender) {
  const policy = await getPolicy();
  if (!policy.reportEndpoint) return;

  const payload = {
    policyId: policy.policyId,
    policyVersion: policy.version,
    extensionVersion: chrome.runtime.getManifest().version,
    browser: "chrome",
    event: {
      action: event.action,
      score: event.score,
      hostname: event.hostname,
      signals: event.signals,
      title: event.title
    },
    tab: sender && sender.tab ? { id: sender.tab.id } : undefined,
    occurredAt: new Date().toISOString()
  };

  try {
    await fetch(policy.reportEndpoint, {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (_) {
    // Reporting must never break page protection.
  }
}

function storageGet(keys) {
  return chrome.storage.local.get(keys);
}

function storageSet(values) {
  return chrome.storage.local.set(values);
}
