// Service-worker logic with mocked Chrome APIs: badges, thresholds, stale updates, "Back to safety".
const assert = require('assert');
const {loadExtension} = require('./load_rules');
const tabs = {5: {id: 5, url: 'https://example.com/login'}};
let page = {ok: true, checked: ['credentials', 'submission', 'pressure'], signals: [], destinations: [], hasPassword: false};
let policy = {protectionEnabled: true, whitelist: []};
let badge = '', title = '', warnCount = 0, lastClear = null, listener = null, updated = null;
const ev = {addListener() {}};
const chrome = {
  tabs: {
    get: async id => tabs[id], query: async () => Object.values(tabs),
    sendMessage: async (_id, msg) => {
      if (msg.type === 'SCAN_DOM') return page;
      if (msg.type === 'PHISH_WARNING') warnCount++;
      if (msg.type === 'CLEAR_WARNING') lastClear = msg;
      return {ok: true};
    },
    update: async (id, props) => {updated = {id, ...props}; return {}; },
    onActivated: ev, onUpdated: ev, onRemoved: ev
  },
  action: {setBadgeText: async ({text}) => {badge = text;}, setBadgeBackgroundColor: async () => {}, setTitle: async ({title: t}) => {title = t;}},
  runtime: {onMessage: {addListener(fn) {listener = fn;}}, getURL: p => 'chrome-extension://abc/' + p},
  storage: {local: {get: async () => ({...policy})}, onChanged: ev}
};
loadExtension({chrome, background: true});
function message(msg, sender = {}) {
  return new Promise((resolve, reject) => {
    const isAsync = listener(msg, sender, resolve);
    if (isAsync === false) setTimeout(() => reject(new Error('Message returned false without response')), 3000);
  });
}
const sig = (id, pts, severity = 'High') => ({id, title: id, desc: id, severity, pts});
(async () => {
  let r = await message({type: 'FULL_SCAN', tabId: 5});
  assert(r.ok && r.full && r.score === 0); assert.strictEqual(badge, '✓');
  assert.strictEqual(lastClear.suppressed, false, 'CLEAR_WARNING tells the page it is not suppressed');

  // Exactly 55 (password form posting to HTTP) is HIGH everywhere now, not "?" in the badge and "!" on the page.
  page = {...page, hasPassword: true, signals: [sig('insecure-action', 55)], destinations: [{host: 'example.com', protocol: 'http:', relation: 'same-host'}]};
  r = await message({type: 'PAGE_SCAN_UPDATE', page}, {tab: {id: 5, url: 'https://example.com/login'}});
  assert(r.ok && r.score === 55); assert.strictEqual(badge, '!'); assert(warnCount === 1); assert(title.includes('55/100'));

  page = {...page, signals: [sig('insecure-action', 55), sig('ext', 28, 'Medium')], destinations: [{host: 'bad.example.net', protocol: 'http:', relation: 'external'}]};
  r = await message({type: 'PAGE_SCAN_UPDATE', page}, {tab: {id: 5, url: 'https://example.com/login'}});
  assert(r.ok && r.score === 83 && r.full); assert.strictEqual(badge, '!');

  // Script-handled forms keep their own label through sanitizing.
  page = {...page, signals: [], destinations: [{host: 'Page script', protocol: 'script:', relation: 'script'}]};
  r = await message({type: 'PAGE_SCAN_UPDATE', page}, {tab: {id: 5, url: 'https://example.com/login'}});
  assert.deepStrictEqual([r.pageResult.destinations[0].protocol, r.pageResult.destinations[0].relation], ['script:', 'script']);
  assert.strictEqual(badge, '✓');

  // Review band starts at 26.
  page = {...page, signals: [sig('ext', 28, 'Medium')]};
  r = await message({type: 'PAGE_SCAN_UPDATE', page}, {tab: {id: 5, url: 'https://example.com/login'}});
  assert.strictEqual(badge, '?');

  policy.protectionEnabled = false;
  r = await message({type: 'REFRESH_BADGE', tabId: 5}); assert.strictEqual(badge, 'OFF'); assert.strictEqual(lastClear.suppressed, true);
  policy.protectionEnabled = true; policy.whitelist = ['example.com'];
  r = await message({type: 'REFRESH_BADGE', tabId: 5}); assert.strictEqual(badge, 'T'); assert.strictEqual(lastClear.suppressed, true);
  policy.whitelist = [];
  page = null;
  r = await message({type: 'FULL_SCAN', tabId: 5}); assert(r.ok && !r.full); assert.strictEqual(badge, '…');

  // Real bank domain is not flagged by the URL rules any more.
  tabs[6] = {id: 6, url: 'https://netbanking.hdfc.bank.in/login'};
  page = {ok: true, checked: ['credentials', 'submission', 'pressure'], signals: [], destinations: [], hasPassword: true};
  r = await message({type: 'FULL_SCAN', tabId: 6}); assert(r.ok && r.score === 0); assert.strictEqual(badge, '✓');

  // "Back to safety" replaces the tab with the extension's safe page (works with no history).
  r = await message({type: 'LEAVE_PAGE'}, {tab: {id: 5, url: 'https://paypa1-secure.xyz/login'}});
  assert(r.ok); assert.strictEqual(updated.id, 5);
  assert.strictEqual(updated.url, 'chrome-extension://abc/safe.html?site=paypa1-secure.xyz');

  tabs[5].url = 'https://another.example.net/';
  r = await message({type: 'PAGE_SCAN_UPDATE', page: {ok: true, checked: ['credentials'], signals: []}}, {tab: {id: 5, url: 'https://example.com/login'}});
  assert(!r.ok && r.error === 'Stale page update');
  console.log('PASS background: clean ✓, score 55 is ! (shared threshold), review ?, script-handled forms, OFF, trusted T, URL-only …, bank.in clean, Back to safety, stale update rejected');
})().catch(e => {console.error(e); process.exitCode = 1;});
