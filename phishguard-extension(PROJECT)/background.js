// PhishGuard 3.5.1 — service worker. On-device explainable heuristics, not a reputation service.
if (typeof importScripts === "function" && !globalThis.PhishGuardRules) importScripts("rules.js");
const RULES = globalThis.PhishGuardRules;
const {HIGH_RISK, REVIEW_RISK} = RULES;

// A single scanner owns tab badges and the popup's full-scan evidence.
// Tab scan results are ephemeral. No form values, credentials or page text are stored.
const TAB_EVIDENCE = new Map();
const PAGE_CHECKS_SET = new Set(["credentials", "submission", "pressure"]);
const totalChecks = 8;

async function readPolicy() {
  const value = await chrome.storage.local.get(["protectionEnabled", "whitelist"]);
  return {
    enabled: value.protectionEnabled !== false,
    whitelist: Array.isArray(value.whitelist) ? value.whitelist : []
  };
}
function trustedHostname(url, policy) {
  try {return policy.whitelist.includes(new URL(url).hostname.toLowerCase());}
  catch {return false;}
}
function sanitizePageData(data) {
  if (!data || data.ok !== true || !Array.isArray(data.checked) || !Array.isArray(data.signals)) return null;
  const checked = [...new Set(data.checked.filter(id => PAGE_CHECKS_SET.has(id)))];
  const signals = data.signals.filter(s => s && typeof s.id === "string" && s.id.length < 70 &&
    typeof s.title === "string" && typeof s.desc === "string" && Number.isFinite(s.pts))
    .slice(0, 15).map(s => ({
      id:s.id, title:s.title.slice(0, 120), desc:s.desc.slice(0, 300),
      severity:["Low", "Medium", "High"].includes(s.severity) ? s.severity : "Low",
      pts:Math.max(0, Math.min(100, s.pts)), source:"page"
    }));
  const destinations = Array.isArray(data.destinations) ? data.destinations.slice(0, 8).map(d => ({
    host:String(d?.host || "Unknown").slice(0, 253),
    protocol:["https:", "http:", "script:", "other:"].includes(d?.protocol) ? d.protocol : "other:",
    relation:["same-host", "same-site", "external", "script", "unknown"].includes(d?.relation) ? d.relation : "unknown",
    password: true
  })) : [];
  return {ok:true, checked, signals, destinations, hasPassword:Boolean(data.hasPassword)};
}
function combineScores(urlResult, pageResult) {
  const unique = new Map();
  for (const signal of [...urlResult.signals, ...(pageResult?.signals || [])]) {
    unique.set(`${signal.source}:${signal.id}`, signal);
  }
  return Math.min(100, [...unique.values()].reduce((n, s) => n + s.pts, 0));
}
async function setBadge(tabId, {score, full = false, enabled = true, trusted = false} = {}) {
  if (!Number.isInteger(tabId)) return;
  let label, color, title;
  if (!enabled) {label = "OFF"; color = "#64748b"; title = "PhishGuard: local warnings paused globally";}
  else if (trusted) {label = "T"; color = "#478ab2"; title = "PhishGuard: this hostname is trusted, warnings suppressed";}
  else if (score >= HIGH_RISK) {label = "!"; color = "#ef4763"; title = `PhishGuard: high-risk indicators (${score}/100)`;}
  else if (score >= REVIEW_RISK) {label = "?"; color = "#e8a63b"; title = `PhishGuard: review indicators (${score}/100)`;}
  else if (!full) {label = "…"; color = "#7088a5"; title = "PhishGuard: URL-only check; webpage not inspected";}
  else {label = "✓"; color = "#21bd91"; title = `PhishGuard: full local check, ${score}/100 (not a safety guarantee)`;}
  await Promise.allSettled([
    chrome.action.setBadgeBackgroundColor({tabId, color}),
    chrome.action.setBadgeText({tabId, text:label}),
    chrome.action.setTitle?.({tabId, title}) || Promise.resolve()
  ]);
}
async function askContent(tabId) {
  try {return sanitizePageData(await chrome.tabs.sendMessage(tabId, {type:"SCAN_DOM"}));}
  catch {return null;}
}
async function collectTabScan(tabId, allowInjection = false) {
  const tab = await chrome.tabs.get(tabId);
  const url = tab?.url || "";
  const urlResult = RULES.urlScore(url);
  if (!urlResult.ok) {
    TAB_EVIDENCE.delete(tabId);
    await chrome.action.setBadgeText({tabId, text:""}).catch(() => {});
    return {ok:false, error:urlResult.error};
  }
  let pageResult = await askContent(tabId);
  if (!pageResult && allowInjection && chrome.scripting?.executeScript) {
    try {
      await chrome.scripting.executeScript({target:{tabId}, files:["rules.js", "content.js"]});
      pageResult = await askContent(tabId);
    } catch { /* restricted or not yet loaded; URL-only is explicit */ }
  }
  return commitScan(tabId, urlResult, pageResult);
}
async function commitScan(tabId, urlResult, pageResult) {
  const policy = await readPolicy();
  const trusted = trustedHostname(urlResult.url, policy);
  const score = combineScores(urlResult, pageResult);
  const coverage = urlResult.checked.length + (pageResult?.checked.length || 0);
  const full = coverage === totalChecks;
  TAB_EVIDENCE.set(tabId, {url:urlResult.url, pageResult, score, full});
  await setBadge(tabId, {score, full, enabled:policy.enabled, trusted});
  if (policy.enabled && !trusted && score >= HIGH_RISK) {
    chrome.tabs.sendMessage(tabId, {type:"PHISH_WARNING", score}).catch(() => {});
  } else {
    // The page re-checks its own evidence; it only removes warnings when suppressed or when its local score is low.
    chrome.tabs.sendMessage(tabId, {type:"CLEAR_WARNING", suppressed:!policy.enabled || trusted}).catch(() => {});
  }
  return {ok:true, urlResult, pageResult, score, full, enabled:policy.enabled, trusted};
}
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.status === "loading" || typeof change.url === "string") {
    TAB_EVIDENCE.delete(tabId);
    chrome.action.setBadgeText({tabId, text:""}).catch(() => {});
  }
  if (change.status === "complete" && /^https?:\/\//.test(tab?.url || "")) {
    collectTabScan(tabId, false).catch(() => {});
  }
});
chrome.tabs.onActivated.addListener(({tabId}) => collectTabScan(tabId, false).catch(() => {}));
chrome.tabs.onRemoved?.addListener(tabId => TAB_EVIDENCE.delete(tabId));
chrome.storage.onChanged?.addListener((changes, area) => {
  if (area !== "local" || !(changes.protectionEnabled || changes.whitelist)) return;
  chrome.tabs.query({}).then(tabs => {
    for (const tab of tabs) if (Number.isInteger(tab.id) && /^https?:\/\//.test(tab.url || "")) {
      const last = TAB_EVIDENCE.get(tab.id);
      const check = RULES.urlScore(tab.url);
      if (!check.ok) continue;
      // Use cached page evidence only for the exact same URL.
      commitScan(tab.id, check, last?.url === check.url ? last.pageResult : null).catch(() => {});
    }
  }).catch(() => {});
});
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg?.type === "PAGE_SCAN_UPDATE") {
    // Trust tab URL provided by Chrome, not a URL claimed by the page.
    if (!Number.isInteger(sender?.tab?.id) || !/^https?:\/\//.test(sender.tab.url || "")) {
      respond({ok:false, error:"No originating website tab"}); return false;
    }
    const tabId = sender.tab.id, urlResult = RULES.urlScore(sender.tab.url);
    const pageResult = sanitizePageData(msg.page);
    if (!urlResult.ok || !pageResult) {respond({ok:false, error:"Invalid page evidence"}); return false;}
    // Ignore stale async DOM updates from a document no longer at this URL.
    chrome.tabs.get(tabId).then(tab => {
      if (tab.url !== sender.tab.url) return {ok:false, error:"Stale page update"};
      return commitScan(tabId, urlResult, pageResult);
    }).then(respond).catch(e => respond({ok:false, error:e.message}));
    return true;
  }
  if (msg?.type === "LEAVE_PAGE") {
    // "Back to safety": replace the flagged page with PhishGuard's own page. Works even when the
    // tab has no history (links opened from email or chat) and avoids bouncing through redirectors.
    const tabId = sender?.tab?.id;
    if (!Number.isInteger(tabId)) {respond({ok:false, error:"No originating tab"}); return false;}
    let site = "";
    try {site = new URL(sender.tab.url).hostname;} catch {}
    chrome.tabs.update(tabId, {url:chrome.runtime.getURL("safe.html") + "?site=" + encodeURIComponent(site)})
      .then(() => respond({ok:true})).catch(e => respond({ok:false, error:e.message}));
    return true;
  }
  if (msg?.type === "FULL_SCAN" || msg?.type === "REFRESH_BADGE") {
    if (!Number.isInteger(msg.tabId)) {respond({ok:false, error:"Invalid tab"}); return false;}
    collectTabScan(msg.tabId, msg.type === "FULL_SCAN")
      .then(respond).catch(e => respond({ok:false, error:e.message}));
    return true;
  }
  return false;
});
