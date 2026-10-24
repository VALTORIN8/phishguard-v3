// PhishGuard 3.5.1. Inspect structural metadata only: never access input.value or credentials.
// rules.js is loaded first (manifest and scripting injection) and provides PhishGuardRules.
(() => {
  if (globalThis.__phishguardContentLoaded) return;
  const R = globalThis.PhishGuardRules;
  if (!R) return;
  globalThis.__phishguardContentLoaded = true;
  const HIGH = R.HIGH_RISK, REVIEW = R.REVIEW_RISK;
  const URGENT_DEBOUNCE = 380, SLOW_INTERVAL = 3000;
  const RELEVANT = "form,input,button,iframe";

  let globalEnabled = true, trusted = false, pageScore = 0, lastFingerprint = "", lastDom = null;
  let hoverTimer = null, scanTimer = null, slowTimer = null, lastScanAt = 0, tip = null;
  let bannerDismissedAt = -1;  // banner stays hidden until risk rises above this score
  let guardAcceptedAt = -1;    // password guard stays quiet until risk rises above this score
  let guardOpen = false;
  const bypassSubmit = new WeakSet();
  const urlCache = {href:null, result:null};
  const isSuppressed = () => !globalEnabled || trusted;

  function currentUrlResult() {
    if (urlCache.href !== location.href) {urlCache.href = location.href; urlCache.result = R.urlScore(location.href);}
    return urlCache.result;
  }
  async function refreshPolicy() {
    try {
      const settings = await chrome.storage.local.get(["protectionEnabled", "whitelist"]);
      globalEnabled = settings.protectionEnabled !== false;
      trusted = Array.isArray(settings.whitelist) && settings.whitelist.includes(location.hostname.toLowerCase());
    } catch {globalEnabled = true; trusted = false;}
    if (isSuppressed()) clearWarnings();
    return !isSuppressed();
  }
  function clearWarnings() {
    clearTimeout(hoverTimer);
    tip?.remove(); tip = null;
    document.getElementById("pg-banner")?.remove();
    document.getElementById("pg-guardian")?.remove();
    guardOpen = false;
  }
  function send(message) {
    try {return Promise.resolve(chrome.runtime.sendMessage(message)).catch(() => null);}
    catch {return Promise.resolve(null);} // extension reloaded or worker restarting
  }
  function formDestinations() {
    const passwords = [...document.querySelectorAll('input[type="password"]')].slice(0, 60);
    const forms = [...new Set(passwords.map(field => field.form).filter(Boolean))].slice(0, 12);
    const results = [];
    for (const form of forms) {
      // Only read the declared destination URL, never form field values.
      const actions = [form.getAttribute("action") || location.href];
      for (const button of form.querySelectorAll("[formaction]")) {
        if (actions.length >= 5) break;
        if (button.getAttribute("formaction")) actions.push(button.getAttribute("formaction"));
      }
      for (const raw of [...new Set(actions.map(a => String(a).trim()))]) {
        if (/^javascript:/i.test(raw)) {
          // Submission is handled by the page's own script; the real destination is not declared.
          results.push({host:"Page script", protocol:"script:", relation:"script", password:true});
        } else {
          let host = "Unknown", protocol = "other:", relation = "unknown";
          try {
            const target = new URL(raw || location.href, location.href);
            protocol = ["https:", "http:"].includes(target.protocol) ? target.protocol : "other:";
            host = target.hostname.toLowerCase() || "Unknown";
            if (protocol !== "other:") {
              relation = host === location.hostname ? "same-host" : R.sameSite(host, location.hostname) ? "same-site" : "external";
            }
          } catch { /* an unparsable target is reported as an invalid destination */ }
          results.push({host, protocol, relation, password:true});
        }
        if (results.length >= 8) return results;
      }
    }
    return results;
  }
  function scanDOM() {
    const signals = [];
    const add = (id, title, desc, severity, pts) => signals.push({id, title, desc, severity, pts, source:"page"});
    const hasPassword = Boolean(document.querySelector('input[type="password"]'));
    const destinations = formDestinations();
    // Read visible page labels for fixed known phrases, not the contents of any input/textarea.
    let phrases = [];
    if (hasPassword && document.body) {
      const txt = (document.body.innerText || "").toLowerCase().slice(0, 40000);
      const urgency = ["account suspended", "verify immediately", "confirm your identity", "account will be blocked", "unauthorized access", "immediate verification", "urgent action required"];
      phrases = urgency.filter(phrase => txt.includes(phrase));
    }
    const insecureTarget = d => d.protocol === "other:" || (d.protocol === "http:" && !R.isLoopback(d.host));
    if (hasPassword && location.protocol === "http:" && !R.isLoopback(location.hostname)) add("insecure-pass", "Password requested over HTTP", "This page requests a password without HTTPS encryption. Do not enter your credentials.", "High", 55);
    if (destinations.some(insecureTarget)) add("insecure-action", "Insecure or invalid password destination", "A password form may send credentials through HTTP or an invalid destination. Check before proceeding.", "High", 55);
    if (destinations.some(d => d.relation === "external")) add("ext", "External password destination", "A password form targets a different website. This may be legitimate single sign-on, but verify it independently.", "Medium", 28);
    if (phrases.length) add("urg", "Urgency language on a sign-in page", `This page requests a password while showing “${phrases[0]}”.`, "Medium", 18);
    return {ok:true, checked:["credentials", "submission", "pressure"], signals,
      score:Math.min(100, signals.reduce((n, s) => n + s.pts, 0)), hasPassword, destinations};
  }
  function combinedScore(dom) {
    const url = currentUrlResult();
    const unique = new Map();
    for (const s of [...(url?.ok ? url.signals : []), ...dom.signals]) unique.set(`${s.source}:${s.id}`, s);
    return Math.min(100, [...unique.values()].reduce((n, s) => n + s.pts, 0));
  }
  function leavePage() {
    send({type:"LEAVE_PAGE"}).then(res => {if (!res?.ok) history.back();});
  }
  function showGuardian({score, field = null, onContinue = null}) {
    if (isSuppressed() || guardOpen || !document.documentElement) return;
    guardOpen = true;
    const root = document.createElement("div"); root.id = "pg-guardian";
    root.innerHTML = `<div class="pg-g-backdrop"><div class="pg-g-modal" role="alertdialog" aria-modal="true" aria-label="Suspicious credential destination"><div style="font-size:38px">⚠️</div><h2>Password warning</h2><p>PhishGuard found high-risk URL or password-form indicators. Check the website and form destination before sharing a password.</p><div class="pg-g-btns"><button class="pg-g-safe">Back to safety</button><button class="pg-g-risk">Continue anyway</button></div></div></div>`;
    document.documentElement.appendChild(root);
    const close = () => {root.remove(); guardOpen = false;};
    root.querySelector(".pg-g-safe").addEventListener("click", () => {close(); leavePage();});
    root.querySelector(".pg-g-risk").addEventListener("click", () => {
      // Remember the choice for this page so the field can actually be used.
      guardAcceptedAt = Math.max(guardAcceptedAt, score);
      close();
      if (onContinue) onContinue();
      else if (field?.isConnected) field.focus();
    });
    root.addEventListener("keydown", e => {if (e.key === "Escape") {e.stopPropagation(); close();}});
    root.querySelector(".pg-g-safe").focus();
  }
  function showBanner(score) {
    if (isSuppressed() || !document.documentElement || score < HIGH || score <= bannerDismissedAt || document.getElementById("pg-banner")) return;
    const banner = document.createElement("div"); banner.id = "pg-banner";
    banner.innerHTML = `<div class="pg-ban" role="alert"><div class="pg-ban-l"><span style="font-size:22px">🚨</span><div><b>PhishGuard — check this website</b><div>Suspicious URL or login-form indicators detected. Verify the destination before sharing credentials.</div></div></div><div class="pg-ban-r"><button class="pg-ban-back">Back to safety</button><button class="pg-ban-x">Dismiss</button></div></div>`;
    document.documentElement.appendChild(banner);
    banner.querySelector(".pg-ban-back").addEventListener("click", leavePage);
    banner.querySelector(".pg-ban-x").addEventListener("click", () => {bannerDismissedAt = score; banner.remove();});
  }
  function updateLocalRisk(dom) {
    if (isSuppressed()) return;
    pageScore = combinedScore(dom);
    if (pageScore >= HIGH) showBanner(pageScore);
    else {document.getElementById("pg-banner")?.remove(); bannerDismissedAt = -1;}
  }
  function publish(dom) {
    const fingerprint = JSON.stringify({url:location.href, signals:dom.signals.map(s => s.id), destinations:dom.destinations, hasPassword:dom.hasPassword});
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;
    send({type:"PAGE_SCAN_UPDATE", page:dom});
  }
  function refreshScore() {
    clearTimeout(scanTimer); scanTimer = null;
    lastScanAt = Date.now();
    const dom = scanDOM();
    lastDom = dom;
    publish(dom);
    updateLocalRisk(dom);
    return dom;
  }
  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(refreshScore, URGENT_DEBOUNCE);
  }
  // Non-form changes (feeds, clocks, ads) only matter for urgency text on sign-in pages: at most one scan per 3 s.
  function scheduleSlowScan() {
    if (slowTimer || scanTimer) return;
    const wait = Math.max(URGENT_DEBOUNCE, SLOW_INTERVAL - (Date.now() - lastScanAt));
    slowTimer = setTimeout(() => {slowTimer = null; refreshScore();}, wait);
  }
  function showTip(link) {
    if (isSuppressed() || !link?.isConnected || !/^https?:\/\//i.test(link.href)) return;
    const href = link.href;
    const res = R.urlScore(href);
    if (!res?.ok) return;
    tip?.remove();
    tip = document.createElement("div"); tip.id = "pg-tip";
    const top = document.createElement("div"); top.className = "pg-tip-h";
    const name = document.createElement("b"); name.textContent = "🛡️ PhishGuard";
    const level = document.createElement("span");
    level.style.color = res.score >= HIGH ? "#fb7185" : res.score >= REVIEW ? "#ffbf55" : "#34ddb0";
    level.textContent = `${res.score >= HIGH ? "HIGH RISK" : res.score >= REVIEW ? "REVIEW" : "LOW URL RISK"} · ${res.score}/100`;
    top.append(name, level);
    const addr = document.createElement("div"); addr.className = "pg-tip-u"; addr.textContent = href.slice(0, 120);
    const clues = document.createElement("div"); clues.className = "pg-tip-r";
    clues.textContent = res.signals.slice(0, 3).map(s => "• " + s.title).join(" · ") || "URL-only assessment; destination webpage not inspected";
    tip.append(top, addr, clues); document.documentElement.appendChild(tip);
    const r = link.getBoundingClientRect();
    tip.style.top = Math.max(8, Math.min(r.bottom + 8, innerHeight - 125)) + "px";
    tip.style.left = Math.max(8, Math.min(r.left, innerWidth - 325)) + "px";
  }
  const touchesForms = n => n.nodeType === 1 && (n.matches?.(RELEVANT) || Boolean(n.querySelector?.(RELEVANT)));
  // Password fields may appear after initial load (SPA/JavaScript sign-in).
  const observer = new MutationObserver(mutations => {
    let urgent = false, other = false;
    for (const m of mutations) {
      const el = m.target?.nodeType === 1 ? m.target : m.target?.parentElement;
      if (el?.closest?.("#pg-banner,#pg-guardian,#pg-tip")) continue;
      if (m.type === "attributes" || [...m.addedNodes].some(touchesForms) || [...m.removedNodes].some(touchesForms)) {urgent = true; break;}
      if (m.addedNodes.length) other = true;
    }
    if (urgent) scheduleScan();
    else if (other && lastDom?.hasPassword) scheduleSlowScan();
  });
  // document_start runs before the webpage DOM is fully constructed.
  function attachObserver() {
    if (!document.documentElement) {setTimeout(attachObserver, 25); return;}
    observer.observe(document.documentElement, {subtree:true, childList:true, attributes:true, attributeFilter:["action", "formaction", "type"]});
    scheduleScan();
  }
  attachObserver();
  document.addEventListener("focusin", event => {
    if (isSuppressed() || guardOpen || !(event.target instanceof Element) || !event.target.matches('input[type="password"]')) return;
    const dom = refreshScore();
    const score = combinedScore(dom);
    if (score >= HIGH && score > guardAcceptedAt) {event.target.blur(); showGuardian({score, field:event.target});}
  }, true);
  document.addEventListener("submit", event => {
    if (isSuppressed() || !(event.target instanceof HTMLFormElement) || !event.target.querySelector('input[type="password"]')) return;
    const form = event.target;
    if (bypassSubmit.has(form)) {bypassSubmit.delete(form); return;}
    // Only interrupt when current risk is high and the user has not already chosen to continue; no password value is read.
    const score = combinedScore(scanDOM());
    if (score < HIGH || score <= guardAcceptedAt) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const submitter = event.submitter;
    showGuardian({score, onContinue:() => {
      bypassSubmit.add(form);
      try {submitter ? form.requestSubmit(submitter) : form.requestSubmit();}
      catch {bypassSubmit.delete(form);}
    }});
  }, true);
  document.addEventListener("mouseover", event => {
    if (isSuppressed() || !(event.target instanceof Element)) return;
    const a = event.target.closest("a[href]");
    if (!a || !/^https?:\/\//i.test(a.href)) return;
    clearTimeout(hoverTimer); hoverTimer = setTimeout(() => showTip(a), 400);
  });
  document.addEventListener("mouseout", () => {clearTimeout(hoverTimer); tip?.remove(); tip = null;});
  document.addEventListener("scroll", () => {tip?.remove(); tip = null;}, true);
  document.addEventListener("DOMContentLoaded", scheduleScan);
  window.addEventListener("hashchange", scheduleScan);
  window.addEventListener("popstate", scheduleScan);
  window.addEventListener("pageshow", scheduleScan);
  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (msg?.type === "SCAN_DOM") {reply(scanDOM()); return false;}
    if (msg?.type === "PHISH_WARNING") {pageScore = Math.max(pageScore, Number(msg.score) || 0); showBanner(pageScore); return false;}
    if (msg?.type === "CLEAR_WARNING") {
      // The worker may not have this page's evidence yet; only drop warnings when suppressed or locally low.
      if (msg.suppressed) refreshPolicy(); else refreshScore();
      return false;
    }
    if (msg?.type === "TOGGLE_SITE") {trusted = Boolean(msg.disabled); if (isSuppressed()) clearWarnings(); else refreshScore(); return false;}
    if (msg?.type === "PROTECTION_CHANGED") {globalEnabled = Boolean(msg.enabled); if (isSuppressed()) clearWarnings(); else refreshScore(); return false;}
    return false;
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && (changes.whitelist || changes.protectionEnabled)) {
      refreshPolicy().then(active => {if (active) refreshScore();});
    }
  });
  refreshPolicy().then(() => refreshScore());
})();
