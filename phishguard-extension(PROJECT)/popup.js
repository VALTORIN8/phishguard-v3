// PhishGuard v3.5.1 — suspicion, evidence quality, and actual check coverage are distinct.
// No probability or claim of validated classification accuracy is produced.
const RULES = globalThis.PhishGuardRules;
const CONTACT_EMAIL = "its.yugi.itadori@gmail.com"; // where "Contact developer" drafts are addressed
const CHECKS = [
  {id:"transport", label:"Transport security", group:"url", detail:"Checks HTTP versus HTTPS and unusual ports. HTTPS alone does not prove trustworthiness."},
  {id:"domain", label:"Domain patterns", group:"url", detail:"Checks unusual endings, IP destinations, and encoded hostnames."},
  {id:"identity", label:"Brand lookalikes", group:"url", detail:"Looks for brand impersonation, visually similar spellings, and misleading subdomains."},
  {id:"structure", label:"URL structure", group:"url", detail:"Inspects length, nested subdomains, hyphens, and @-style deception."},
  {id:"wording", label:"URL language", group:"url", detail:"Looks for multiple urgent account-related terms in the URL."},
  {id:"credentials", label:"Login forms", group:"page", detail:"Checks whether password inputs occur on insecure pages; never reads values."},
  {id:"submission", label:"Form destinations", group:"page", detail:"Examines declared password-form destinations for external or insecure targets."},
  {id:"pressure", label:"Pressure tactics", group:"page", detail:"Looks for common urgency phrases on pages requesting passwords."}
];
const byId = id => document.getElementById(id);
const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const asNumber = (n, fallback = 0) => Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : fallback;
const severityClass = s => s === "High" ? "high" : s === "Medium" ? "medium" : "low";
const riskLevel = score => score >= RULES.HIGH_RISK ? {label:"HIGH RISK", color:"#fb7185", icon:"!", guide:"Avoid credentials and payments. Verify the real domain separately.", tag:"DANGER"} :
  score >= RULES.REVIEW_RISK ? {label:"CAUTION", color:"#ffbf55", icon:"!", guide:"Some warning signs were found. Double-check the address.", tag:"REVIEW"} :
  {label:"LOW RISK", color:"#34ddb0", icon:"✓", guide:"No strong phishing indicators found in the checks performed.", tag:"CHECKED"};

let currentHost = null, currentTabId = null, currentUrl = null, lastResult = null;
let protectionEnabled = true;
let runNumber = 0;

function makeAssessment(urlData, pageData = null) {
  if (!urlData?.ok || !Array.isArray(urlData.checked) || !Array.isArray(urlData.signals)) return null;
  const pageOk = Boolean(pageData?.ok && Array.isArray(pageData.checked) && Array.isArray(pageData.signals));
  const checked = new Set([...urlData.checked, ...(pageOk ? pageData.checked : [])]);
  const unique = new Map();
  for (const signal of [...urlData.signals, ...(pageOk ? pageData.signals : [])]) {
    if (!signal?.id || !Number.isFinite(signal.pts)) continue;
    if (!unique.has(signal.id)) unique.set(signal.id, signal);
  }
  const signals = [...unique.values()].sort((a, b) => b.pts - a.pts);
  const score = Math.min(100, signals.reduce((sum, s) => sum + s.pts, 0));
  const covered = CHECKS.filter(item => checked.has(item.id)).length;
  const coveragePct = Math.round(100 * covered / CHECKS.length);
  // Describe evidence provenance, not a statistical likelihood or calibration score.
  const sources = new Set(signals.map(s => s.source || (s.id === "ext" || s.id === "urg" || s.id === "insecure-pass" ? "page" : "url")));
  const corroborated = sources.has("page") && sources.has("url") && signals.length >= 2;
  const evidence = !pageOk ?
    {label:"URL-only", detail:"URL clues only; page behavior was not inspected."} :
    corroborated ? {label:"Combined clues", detail:"URL and page checks both raised concerns; some signals may be related."} :
    {label:"Broader scan", detail:"URL and page structure checked; this is not proof of safety."};
  return {
    domain:urlData.domain, url:urlData.url, score, covered,
    pageResult:pageOk ? pageData : null,
    coveragePct, completed:checked, signals, pageOk,
    partial:covered < CHECKS.length, evidence
  };
}
function paintExplain(result = null) {
  const completed = result?.completed || new Set();
  byId("explainStatus").textContent = result ? `${result.covered} / ${CHECKS.length} evaluated` : "Awaiting scan";
  byId("explainGrid").innerHTML = CHECKS.map(item => {
    const ok = completed.has(item.id);
    return `<article class="explain-item ${ok ? "done" : "missed"}"><div class="explain-title"><span>${ok ? "✓" : "—"}</span>${escapeHtml(item.label)}</div><div class="explain-detail">${escapeHtml(item.detail)}</div><div class="explain-state">${ok ? "Completed" : "Not inspected"} · ${item.group === "url" ? "URL" : "Webpage"}</div></article>`;
  }).join("");
}
function paintChecks(checked = new Set(), error = false) {
  byId("checksGrid").innerHTML = CHECKS.map(item => {
    const ok = checked.has(item.id);
    return `<div class="check ${ok ? 'ok' : 'skip'}" title="${ok ? 'Completed' : error ? 'Not completed' : 'Unavailable in this scan'}"><span class="check-icon">${ok ? '✓' : '–'}</span><span class="check-name">${escapeHtml(item.label)}</span></div>`;
  }).join("");
}
function paintError(message) {
  lastResult = null;
  byId("domName").textContent = currentHost || "Unavailable website";
  byId("scanTime").textContent = "Scan not completed";
  byId("scanTag").textContent = "NO RESULT";
  byId("scanTag").className = "scan-tag partial";
  paintDestinations(null);
  byId("verIcon").textContent = "!";
  byId("verTitle").textContent = "SCAN UNAVAILABLE";
  byId("verTitle").style.color = "#ffbf55";
  byId("verDesc").textContent = message;
  byId("sigCount").textContent = "—";
  byId("scoreNum").textContent = "—";
  byId("ring").style.background = "#30425a";
  byId("riskText").textContent = "Unknown";
  byId("riskText").style.color = "#e4b05f";
  byId("confNum").textContent = "Unknown";
  byId("confExplain").textContent = "Evidence unavailable; no assessment could be made.";
  byId("coverageNum").textContent = "0";
  byId("coverageBar").style.width = "0%";
  byId("coverageExplain").textContent = "No checks completed";
  byId("checksStatus").textContent = "Unavailable";
  byId("findingCount").textContent = "Unknown";
  byId("evidence").innerHTML = `<div class="empty warn">⚠ Scan did not complete. No safety verdict is available.</div>`;
  byId("guideBox").textContent = "Don't assume this website is safe. Verify its address independently.";
  byId("summaryTitle").textContent = "Assessment unavailable";
  byId("summaryText").textContent = "The scan could not finish. Check the current tab.";
  byId("btnExport").disabled = true;
  paintChecks(new Set(), true);
  paintExplain();
}
function renderAssessment(result, protectionOff = false) {
  lastResult = result;
  const risk = riskLevel(result.score);
  const partial = result.partial;
  byId("domName").textContent = result.domain || "Unknown domain";
  byId("scanTime").textContent = "Checked " + new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
  byId("scanTag").textContent = protectionOff ? (protectionEnabled ? "TRUSTED" : "PAUSED") : partial ? "PARTIAL" : risk.tag;
  byId("scanTag").className = "scan-tag" + (partial || protectionOff ? " partial" : " ok");
  paintDestinations(result.pageResult);
  byId("verIcon").textContent = protectionOff ? "Ⅱ" : partial && result.score < RULES.REVIEW_RISK ? "◷" : risk.icon;
  byId("verTitle").textContent = protectionOff ? (protectionEnabled ? "TRUSTED HOST" : "PROTECTION OFF") : partial && result.score < RULES.REVIEW_RISK ? "PARTIAL SCAN" : risk.label;
  byId("verTitle").style.color = protectionOff ? "#aabbd2" : partial && result.score < RULES.REVIEW_RISK ? "#ffbf55" : risk.color;
  byId("verDesc").textContent = protectionOff ? (protectionEnabled ? "You trusted this hostname, so local warnings are suppressed. Scan results are informational." : "Automatic warnings are paused globally. These results are informational.") :
    partial ? "URL checks completed. " + (result.pageError ? "Page inspection unavailable." : "Some page checks unavailable.") :
    result.score < RULES.REVIEW_RISK ? "No strong phishing clues in the inspected URL and page. This does not guarantee safety." :
    "Potential phishing clues detected by local heuristic checks.";
  byId("sigCount").textContent = result.signals.length;
  byId("scoreNum").textContent = result.score;
  byId("scoreNum").style.color = risk.color;
  const pct = Math.max(result.score, 1);
  byId("ring").style.background = `conic-gradient(${risk.color} ${pct * 3.6}deg, #30435b ${pct * 3.6}deg 360deg)`;
  byId("riskText").textContent = risk.label === "LOW RISK" && partial ? "URL-only" : risk.label === "LOW RISK" ? "Low" : risk.label === "CAUTION" ? "Elevated" : "High";
  byId("riskText").style.color = risk.color;
  byId("confNum").textContent = result.evidence.label;
  byId("confExplain").textContent = result.evidence.detail;
  byId("coverageNum").textContent = result.covered;
  byId("coverageBar").style.width = result.coveragePct + "%";
  byId("coverageExplain").textContent = result.coveragePct + "% of defined local checks";
  byId("checksStatus").textContent = `${result.covered} of ${CHECKS.length} done`;
  byId("checksStatus").title = result.pageError || "Completed checks versus unavailable checks";
  byId("findingCount").textContent = result.signals.length ? `${result.signals.length} signal${result.signals.length === 1 ? "" : "s"}` : "Clear so far";
  byId("summaryTitle").textContent = result.signals.length ? `${result.signals.length} suspicious indicator${result.signals.length === 1 ? "" : "s"}` : result.partial ? "URL check clear so far" : "No signals in completed checks";
  byId("summaryText").textContent = result.partial ? `${result.covered}/8 checks complete · some page signals unavailable` : `All 8 checks complete · local heuristic assessment`;
  paintChecks(result.completed);
  paintExplain(result);
  byId("evidence").innerHTML = result.signals.length ? result.signals.map((sig, index) =>
    `<div class="ev"><span class="ev-index">${index + 1}</span><div class="ev-copy"><h4>${escapeHtml(sig.title)} <small class="points">+${escapeHtml(sig.pts)} points · ${escapeHtml(sig.source || "url")} clue</small></h4><p>${escapeHtml(sig.desc)}</p></div><span class="pill ${severityClass(sig.severity)}">${escapeHtml(sig.severity)}</span></div>`).join("") :
    `<div class="empty">✓ No indicators detected ${partial ? "by URL-only checks." : "in the completed checks."}</div>`;
  byId("guideBox").textContent = protectionOff ? (protectionEnabled ? "Trusted host: remove it in Settings to restore warnings." : "Global warnings are paused. Re-enable them using the switch.") : partial && result.score < RULES.REVIEW_RISK ? "Partial assessment: " + (result.pageError || "Some checks were unavailable.") : risk.guide;
  byId("btnExport").disabled = false;
  if (!protectionOff && result.domain) saveHist(result.domain, partial && result.score < RULES.REVIEW_RISK ? "PARTIAL" : risk.label, result.score, result.covered);
}
async function saveHist(domain, verdict, score, coverage) {
  try {
    const {scanHistory = []} = await chrome.storage.local.get("scanHistory");
    const list = Array.isArray(scanHistory) ? scanHistory : [];
    const updated = [{domain, verdict, score, coverage, time:new Date().toLocaleString()}, ...list.filter(x => x.domain !== domain)].slice(0, 25);
    await chrome.storage.local.set({scanHistory:updated});
  } catch {}
}
async function renderHist() {
  const {scanHistory = []} = await chrome.storage.local.get("scanHistory");
  byId("histBody").innerHTML = Array.isArray(scanHistory) && scanHistory.length ? scanHistory.map(h => {
    const key = h.verdict === "LOW RISK" || h.verdict === "SAFE" ? "safe" : h.verdict === "HIGH RISK" ? "bad" : h.verdict === "PARTIAL" ? "off" : "sus";
    return `<tr><td>${escapeHtml(h.domain)}</td><td><span class="vp ${key}">${escapeHtml(h.verdict)}</span></td><td>${escapeHtml(h.score)}/100</td><td>${Number.isFinite(h.coverage) ? h.coverage + "/8" : "—"}</td><td>${escapeHtml(h.time)}</td></tr>`;
  }).join("") : '<tr><td colspan="5">No scans saved yet</td></tr>';
}
// The allowlist matches exact hostnames only; it never asserts that a site is safe.
function normalizeTrustedHost(input) {
  const value = String(input || "").trim();
  if (!value || /[\s*\\]/.test(value)) throw Error("Enter a valid hostname without spaces or wildcards.");
  if (value.startsWith("//")) throw Error("Enter a hostname or an http(s) URL.");
  let parsed;
  try { parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : "https://" + value); }
  catch { throw Error("Enter a valid hostname or website URL."); }
  if (!["http:","https:"].includes(parsed.protocol) || parsed.username || parsed.password || !parsed.hostname) {
    throw Error("Only normal HTTP or HTTPS website addresses are supported.");
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (host.length > 253 || !/^[a-z0-9.-]+$/.test(host) || host.startsWith(".") || host.endsWith(".") || host.includes("..") || host.split(".").some(label => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) {
    throw Error("Enter a valid exact hostname, such as example.com.");
  }
  if (!host.includes(".") && host !== "localhost") throw Error("Enter a complete hostname, such as example.com.");
  return host;
}
async function readTrustedHosts() {
  const {whitelist = []} = await chrome.storage.local.get("whitelist");
  return Array.isArray(whitelist) ? [...new Set(whitelist.filter(x => typeof x === "string"))] : [];
}
async function renderWhitelist() {
  const list = await readTrustedHosts();
  const root = byId("wlList"); root.replaceChildren();
  byId("trustedCount").textContent = `(${list.length})`;
  byId("btnClearWl").disabled = !list.length;
  const onCurrent = !!currentHost && list.includes(currentHost);
  byId("trustCurrentHost").textContent = currentHost || "No inspectable website";
  byId("trustCurrentStatus").textContent = !currentHost ? "Open an HTTP(S) webpage first." : onCurrent ? "Trusted · warnings paused on this hostname" : "Warnings enabled on this hostname";
  byId("btnTrustCurrent").disabled = !currentHost;
  byId("btnTrustCurrent").textContent = onCurrent ? "Remove trust" : "Trust site";
  if (!list.length) {const empty=document.createElement("div");empty.className="trusted-empty";empty.textContent="No trusted sites yet. Add one above or use ‘Trust this site’ in Overview.";root.append(empty);return;}
  for (const host of list.sort()) {
    const row=document.createElement("div");row.className="trusted-row";
    const name=document.createElement("span");name.textContent=host;name.title=host;
    const remove=document.createElement("button");remove.className="btn ghost";remove.textContent="Remove";remove.setAttribute("aria-label",`Remove ${host} from trusted sites`);
    remove.addEventListener("click",()=>updateTrust(host,false));
    row.append(name,remove);root.append(row);
  }
}
function setTrustControls(trusted) {
  setProtectionView(protectionEnabled);
  byId("btnQuickTrust").disabled = !currentHost;
  byId("btnQuickTrust").textContent = trusted ? "Remove trust" : "Trust this site";
  byId("btnQuickTrust").classList.toggle("is-trusted",trusted);
  byId("btnQuickTrust").setAttribute("aria-pressed",String(trusted));
}
async function updateTrust(host, trust) {
  const sites=new Set(await readTrustedHosts());
  trust ? sites.add(host) : sites.delete(host);
  await chrome.storage.local.set({whitelist:[...sites]});
  if (host === currentHost) {
    setTrustControls(trust);
    if (Number.isInteger(currentTabId)) {
      chrome.tabs.sendMessage(currentTabId,{type:"TOGGLE_SITE",disabled:trust},()=>void chrome.runtime.lastError);
      sendMessage({type:"REFRESH_BADGE",tabId:currentTabId,url:currentUrl},()=>{});
    }
    if (currentUrl) runScan(currentUrl);
  }
  await renderWhitelist();
  toast(trust ? `${host} trusted · warnings paused` : `${host} removed · warnings enabled`);
}
function confirmTrust(host) {
  showDialog({icon:"◇",title:"Trust this hostname?",text:`PhishGuard warnings will be suppressed on ${host} only. This does not verify that the site is legitimate or safe.`,
    steps:["Other subdomains are not automatically trusted.","You can remove this hostname from Settings at any time."],
    confirm:"Trust hostname",cancel:true,action:()=>updateTrust(host,true)});
}
function sendMessage(message, cb) {
  try { chrome.runtime.sendMessage(message, reply => {
    const error = chrome.runtime.lastError;
    cb(error ? {ok:false, error:error.message} : reply);
  }); } catch (e) { cb({ok:false, error:e.message}); }
}
// An existing tab may predate installation/reload of the extension. In that case
// the declarative content script is not yet present, so inject it once and retry.
function requestDomScan(tabId) {
  return new Promise(resolve => {
    try {
      chrome.tabs.sendMessage(tabId, {type:"SCAN_DOM"}, response => {
        const error = chrome.runtime.lastError;
        resolve(error ? {ok:false, error:error.message} : response?.ok ? response : {ok:false, error:"Invalid page scan response."});
      });
    } catch (error) { resolve({ok:false, error:error.message}); }
  });
}
async function getPageScan(tabId) {
  if (!Number.isInteger(tabId)) return {ok:false, error:"Active tab not accessible."};
  let result = await requestDomScan(tabId);
  if (result.ok) return result;
  try {
    await chrome.scripting.executeScript({target:{tabId}, files:["content.js"]});
    result = await requestDomScan(tabId);
  } catch (error) {
    return {ok:false, error:"Page inspection unavailable: " + (error?.message || "restricted webpage")};
  }
  return result;
}
function wait(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
function paintScanning(){
  lastResult=null;
  byId("domName").textContent=currentHost || "Checking current tab";
  byId("scanTime").textContent="Scanning now · URL, page and login forms";
  byId("scanTag").className="scan-tag scanning";
  byId("scanTag").innerHTML='<span class="scan-spinner" aria-hidden="true"></span> SCANNING';
  byId("verIcon").textContent="◌";
  byId("verTitle").textContent="SCANNING…";
  byId("verTitle").style.color="#66bdff";
  byId("verDesc").textContent="Checking URL indicators and inspecting available page structure.";
  byId("sigCount").textContent="—";
  byId("scoreNum").textContent="—";
  byId("ring").style.background="#30435b";
  byId("riskText").textContent="Checking…";
  byId("confNum").textContent="Collecting evidence";
  byId("confExplain").textContent="A fresh local scan is running.";
  byId("coverageNum").textContent="—";
  byId("coverageBar").style.width="0%";
  byId("coverageExplain").textContent="Checks in progress";
  byId("checksStatus").textContent="Scanning…";
  byId("summaryTitle").textContent="Analyzing this page…";
  byId("summaryText").textContent="This is a new scan, not a cached verdict.";
  byId("findingCount").textContent="Scanning";
  byId("evidence").innerHTML='<div class="empty scan-placeholder"><span class="scan-spinner" aria-hidden="true"></span> Inspecting signals…</div>';
  byId("guideBox").textContent="Assessment in progress. Avoid entering sensitive information until the check finishes.";
  byId("btnExport").disabled=true;
  paintChecks(new Set());paintExplain();paintDestinations(null);
}
function paintDestinations(page){
  const label=byId("destinationStatus"), list=byId("destinationList");
  list.replaceChildren();
  const addText=(text)=>{const item=document.createElement("p");item.className="hint";item.textContent=text;list.append(item);};
  if(!page?.ok){label.textContent="Not inspected";addText("Webpage form destinations were unavailable in this scan.");return;}
  if(!page.hasPassword){label.textContent="No password fields";addText("No password fields were detected in the inspected page. Forms that appear later are checked again.");return;}
  label.textContent="Password field detected";
  if(!page.destinations?.length){addText("Password field found, but no HTML form destination was declared. JavaScript may handle submission; destination unknown.");return;}
  for(const item of page.destinations){
    const row=document.createElement("div");row.className="destination-row";
    const host=document.createElement("strong");host.textContent=item.host;
    const info=document.createElement("span");
    info.textContent=item.protocol === "script:" ? "Handled by the page's JavaScript · destination not declared" :
      `${item.protocol === "https:" ? "HTTPS" : item.protocol === "http:" ? "HTTP (unencrypted)" : "Invalid/unknown scheme"} · ${item.relation === "same-host" ? "Current hostname" : item.relation === "same-site" ? "Same website (related subdomain)" : item.relation === "external" ? "External website — check independently" : "Unknown relation"}`;
    row.append(host,info);list.append(row);
  }
}
async function runScan(url) {
  const request=++runNumber;
  paintScanning();
  if (!/^https?:\/\//i.test(url || "") || !Number.isInteger(currentTabId)) {
    paintError("This tab cannot be inspected. Open a normal HTTP(S) webpage.");return;
  }
  // Show real scan progress on every popup open, even when background checks finish very fast.
  const started=Date.now();
  let response;
  try {
    response=await new Promise(resolve=>sendMessage({type:"FULL_SCAN",tabId:currentTabId},resolve));
  } catch(error) {response={ok:false,error:error.message};}
  await wait(Math.max(0,620-(Date.now()-started)));
  if(request!==runNumber)return;
  if(!response?.ok){paintError(response?.error || "The scan could not complete.");return;}
  // Prevent a stale scan response being mistaken for the current website.
  if(response.urlResult?.url!==new URL(url).href){paintError("The tab navigated during scanning. Reopen PhishGuard to rescan.");return;}
  const result=makeAssessment(response.urlResult,response.pageResult);
  if(!result){paintError("Invalid scan result.");return;}
  result.pageError=response.pageResult ? "" : "Page inspection unavailable or blocked by Chrome.";
  renderAssessment(result,!response.enabled || response.trusted);
}
function renderManual(urlResult) {
  if (!urlResult?.ok) {
    byId("manualOut").innerHTML = `<div class="card result-card"><span class="empty warn">⚠ ${escapeHtml(urlResult?.error || "Scan failed. Try a valid http(s) URL.")}</span></div>`;
    return;
  }
  const result = makeAssessment(urlResult);
  if (!result) { byId("manualOut").textContent = "Invalid scan response"; return; }
  const risk = riskLevel(result.score);
  const badge = risk.label === "LOW RISK" ? "LOW URL RISK" : risk.label;
  byId("manualOut").innerHTML = `<section class="card result-card"><div class="result-head"><div><div class="result-domain">${escapeHtml(result.domain)}</div><div class="result-meta">URL-only · ${result.covered}/${CHECKS.length} checks · Evidence: ${escapeHtml(result.evidence.label)}</div></div><div class="result-score" style="color:${risk.color}">${result.score}<span class="metric-unit">/100</span></div></div><div class="result-verdict" style="color:${risk.color}">${badge}</div><p class="hint">Only URL patterns checked, not page content; a low URL score does not establish safety.</p><div class="evidence result-evidence">${result.signals.length ? result.signals.map(s => `<div class="ev"><div class="ev-copy"><h4>${escapeHtml(s.title)} <small class="points">+${escapeHtml(s.pts)} points</small></h4><p>${escapeHtml(s.desc)}</p></div><span class="pill ${severityClass(s.severity)}">${escapeHtml(s.severity)}</span></div>`).join("") : '<div class="empty">✓ No concerning URL patterns found.</div>'}</div></section>`;
  saveHist(result.domain, result.score < RULES.REVIEW_RISK ? "PARTIAL" : risk.label, result.score, result.covered);
}
function navigate(view) {
  document.querySelectorAll(".nav").forEach(btn => btn.classList.toggle("active", btn.dataset.view === view));
  document.querySelectorAll(".view").forEach(el => el.classList.toggle("show", el.id === "view-" + view));
  byId("view-" + view)?.closest(".main")?.scrollTo(0, 0);
  if (view === "history") renderHist();
  if (view === "settings") renderWhitelist();
}
document.querySelectorAll(".nav").forEach(btn => btn.addEventListener("click", () => navigate(btn.dataset.view)));
byId("btnOpenAnalysis").addEventListener("click", () => navigate("analysis"));
byId("btnRescan").addEventListener("click", () => {if(currentUrl)runScan(currentUrl);});
function setProtectionView(on) {
  byId("wlToggle").checked = on;
  byId("wlLabel").textContent = on ? "On" : "Off";
  byId("wlLabel").style.color = on ? "#34ddb0" : "#9aa9c0";
  byId("sidebarStatus").textContent = on ? "Local warnings enabled" : "All warnings paused";
  byId("globalProtectionState").textContent = on ? "On · warnings can appear except on trusted hostnames" : "Off · all automatic page warnings paused";
}
byId("wlToggle").addEventListener("change", async event => {
  const next = event.target.checked;
  byId("wlToggle").disabled = true;
  try {
    await chrome.storage.local.set({protectionEnabled:next});
    protectionEnabled=next;
    setProtectionView(next);
    toast(next ? "Global local warnings resumed" : "Global local warnings paused");
    if(currentUrl) runScan(currentUrl);
  } catch(error) {
    byId("wlToggle").checked = protectionEnabled;
    toast("Could not update global protection: " + error.message,true);
  } finally {byId("wlToggle").disabled=false;}
});
byId("btnQuickTrust").addEventListener("click",async()=>{
  if (!currentHost) return;
  const trusted = (await readTrustedHosts()).includes(currentHost);
  if (trusted) await updateTrust(currentHost,false); else confirmTrust(currentHost);
});
byId("btnTrustCurrent").addEventListener("click",()=>byId("btnQuickTrust").click());
byId("btnAddTrust").addEventListener("click", async()=>{
  let host;
  try {host=normalizeTrustedHost(byId("trustHostInput").value);}catch(e){toast(e.message,true);byId("trustHostInput").focus();return;}
  if ((await readTrustedHosts()).includes(host)) {toast("This hostname is already trusted.");return;}
  showDialog({icon:"◇",title:"Add a trusted hostname?",text:`Suppress PhishGuard warnings on ${host}. This does not validate the site.`,confirm:"Trust hostname",cancel:true,
    action:async()=>{await updateTrust(host,true);byId("trustHostInput").value="";}});
});
byId("trustHostInput").addEventListener("keydown",e=>{if(e.key==="Enter")byId("btnAddTrust").click();});
byId("btnScan").addEventListener("click", () => {
  const input = byId("manualUrl").value.trim();
  if (!input) { byId("manualOut").textContent = "Enter a website URL first."; return; }
  renderManual(RULES.urlScore(input));
});
byId("manualUrl").addEventListener("keydown", e => { if (e.key === "Enter") byId("btnScan").click(); });
document.querySelectorAll(".demo").forEach(btn => btn.addEventListener("click", () => { byId("manualUrl").value = btn.dataset.u; byId("btnScan").click(); }));

// --- NEW: Email Scanner Logic ---
function renderEmailManual(result) {
  if (!result?.ok) {
    byId("emailOut").innerHTML = `<div class="card result-card"><span class="empty warn">⚠ ${escapeHtml(result?.error || "Scan failed.")}</span></div>`;
    return;
  }
  const risk = riskLevel(result.score);
  const badge = risk.label === "LOW RISK" ? "LOW EMAIL RISK" : risk.label;
  byId("emailOut").innerHTML = `<section class="card result-card"><div class="result-head"><div><div class="result-domain">Email Analysis</div><div class="result-meta">Text heuristics</div></div><div class="result-score" style="color:${risk.color}">${result.score}<span class="metric-unit">/100</span></div></div><div class="result-verdict" style="color:${risk.color}">${badge}</div><p class="hint">Analyzed locally based on common phishing text patterns.</p><div class="evidence result-evidence">${result.signals.length ? result.signals.map(s => `<div class="ev"><div class="ev-copy"><h4>${escapeHtml(s.title)} <small class="points">+${escapeHtml(s.pts)} points</small></h4><p>${escapeHtml(s.desc)}</p></div><span class="pill ${severityClass(s.severity)}">${escapeHtml(s.severity)}</span></div>`).join("") : '<div class="empty">✓ No concerning email patterns found in the provided text.</div>'}</div></section>`;
}

byId("btnScanEmail").addEventListener("click", () => {
  const input = byId("manualEmail").value.trim();
  if (!input) { byId("emailOut").innerHTML = `<div class="card result-card"><span class="empty warn">⚠ Enter email text first.</span></div>`; return; }
  renderEmailManual(RULES.emailScore(input));
});
// --------------------------------

byId("btnClearHist").addEventListener("click", () => showDialog({
  icon:"◷", title:"Clear scan history?", text:"This permanently removes locally saved scan results on this browser.",
  confirm:"Clear history", cancel:true, danger:true,
  action:async()=>{await chrome.storage.local.set({scanHistory:[]});await renderHist();toast("History cleared");}
}));
byId("btnClearWl").addEventListener("click", () => showDialog({
  icon:"◇", title:"Remove all trusted sites?", text:"Warnings will be re-enabled for all hostnames previously trusted in this browser.",
  confirm:"Remove all", cancel:true, danger:true,
  action:async()=>{
    await chrome.storage.local.set({whitelist:[]});
    if (currentHost && currentUrl) {
      setTrustControls(false);
      chrome.tabs.sendMessage(currentTabId,{type:"TOGGLE_SITE",disabled:false},()=>void chrome.runtime.lastError);
      sendMessage({type:"REFRESH_BADGE",tabId:currentTabId,url:currentUrl},()=>{});
      runScan(currentUrl);
    }
    await renderWhitelist();toast("All trusted sites removed");
  }
}));
byId("btnReport").addEventListener("click", () => {
  navigate("contact");
  byId("cMsg").value = `Possible false positive on ${currentHost || "a website"}.\nRisk score: ${lastResult?.score ?? "unknown"}/100\nDetected indicators: ${(lastResult?.signals || []).map(s => s.title).join(", ") || "none"}\n\nDetails: `;
  byId("cMsg").focus();
});
byId("btnSandbox").addEventListener("click", () => showDialog({
  icon:"↗", title:"Safer testing tips", text:"PhishGuard does not create a sandbox or isolate a website.",
  steps:["Use a disposable browser profile or an isolated virtual machine.","Never enter real credentials or payment details.","Do not download or execute unknown files."],
  confirm:"Understood"
}));
byId("btnExport").addEventListener("click", async () => {
  if (!lastResult) return;
  const a = lastResult;
  const lines = ["PhishGuard 3.5.1 — LOCAL HEURISTIC REPORT", `Domain: ${a.domain}`, `URL: ${a.url}`, `Risk score: ${a.score}/100 (suspicion, not a probability)`, `Evidence: ${a.evidence.label} — ${a.evidence.detail}`, `Coverage: ${a.covered}/${CHECKS.length} checks (${a.coveragePct}%)`, `Checks completed: ${CHECKS.filter(c => a.completed.has(c.id)).map(c => c.label).join(", ")}`, `Checks unavailable: ${CHECKS.filter(c => !a.completed.has(c.id)).map(c => c.label).join(", ") || "none"}`, `Page scan diagnostic: ${a.pageError || "none"}`, `Indicators (${a.signals.length}):`, ...a.signals.map(s => `- [${s.severity}; +${s.pts} indicators] ${s.title}: ${s.desc}`), "On-device rule-based assessment. Not independently calibrated, not a guarantee of safety."];
  try { await navigator.clipboard.writeText(lines.join("\n")); toast("Security report copied"); }
  catch { toast("Clipboard unavailable. Check browser permissions.",true); }
});
byId("btnUpdates").addEventListener("click", () => showDialog({
  icon:"↻", title:"Update PhishGuard", text:"To install a new ZIP version of this unpacked extension:",
  steps:["Download and extract the updated ZIP.","Open chrome://extensions/ and enable Developer mode.","For a new folder, choose Load unpacked. For the same folder, click Reload.","Refresh any already-open websites before testing."],
  confirm:"Open extensions", action:()=>chrome.tabs.create({url:"chrome://extensions/"})
}));
byId("btnContact").addEventListener("click", () => {
  const name = byId("cName").value.trim() || "User";
  const email = byId("cEmail").value.trim();
  const message = byId("cMsg").value.trim();
  const subject = encodeURIComponent("PhishGuard feedback");
  const body = encodeURIComponent(`From: ${name}\nEmail: ${email}\n\nMessage:\n${message}\n\nSent through PhishGuard.`);
  if (!message) {showContactError("Please describe the issue before composing an email.");return;}
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {showContactError("Enter a valid email address or leave the field empty.");return;}
  showContactError("");
  const link = document.createElement("a");
  link.href = `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`;
  link.click();
  toast("Email draft requested — check your mail app before sending.");
});

// One accessible dialog replaces browser alert/confirm boxes.
let dialogAction = null;
let dialogReturnFocus = null;
function showDialog({icon="ⓘ",title,text,steps=[],confirm="OK",cancel=false,danger=false,action=null}) {
  dialogReturnFocus = document.activeElement;
  dialogAction = action;
  byId("dialogIcon").textContent = icon;
  byId("dialogTitle").textContent = title;
  byId("dialogText").textContent = text;
  byId("dialogSteps").replaceChildren();
  for (const step of steps) {const li=document.createElement("li");li.textContent=step;byId("dialogSteps").append(li);}
  byId("dialogSteps").hidden = !steps.length;
  byId("dialogCancel").hidden = !cancel;
  byId("dialogConfirm").textContent = confirm;
  byId("dialogConfirm").classList.toggle("danger",danger);
  byId("pgDialog").hidden = false;
  byId("dialogConfirm").focus();
}
function closeDialog() {
  byId("pgDialog").hidden=true;
  dialogAction=null;
  dialogReturnFocus?.focus?.();
}
byId("dialogClose").addEventListener("click",closeDialog);
byId("dialogCancel").addEventListener("click",closeDialog);
byId("dialogConfirm").addEventListener("click",async()=>{
  const action=dialogAction;
  closeDialog();
  if(action)try{await action();}catch(e){toast("Action failed: "+(e?.message||"Unknown error"),true);}
});
byId("pgDialog").addEventListener("click",e=>{if(e.target===byId("pgDialog"))closeDialog();});
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!byId("pgDialog").hidden)closeDialog();});
let toastTimer;
function toast(message,error=false){
  const el=byId("pgToast");el.textContent=message;el.classList.toggle("error",error);el.hidden=false;
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.hidden=true,2800);
}
function showContactError(message){
  const el=byId("contactError");el.textContent=message;el.hidden=!message;
}
paintChecks();
paintExplain();
byId("btnExport").disabled = true;
paintScanning();
chrome.tabs.query({active:true, currentWindow:true}, async tabs => {
  try {
    const tab=tabs?.[0];
    if(!tab){paintError("No active browser tab found.");return;}
    currentTabId=tab.id;
    currentUrl=tab.url || "";
    const settings=await chrome.storage.local.get(["whitelist","protectionEnabled"]);
    protectionEnabled=settings.protectionEnabled!==false;
    setProtectionView(protectionEnabled);
    if(!/^https?:\/\//i.test(currentUrl)){
      paintError("This tab is an internal or unsupported page.");byId("btnQuickTrust").disabled=true;return;
    }
    currentHost=new URL(currentUrl).hostname.toLowerCase();
    setTrustControls(Array.isArray(settings.whitelist) && settings.whitelist.includes(currentHost));
    await runScan(currentUrl);
  } catch(error){paintError("Unable to scan the active tab: "+error.message);}
});