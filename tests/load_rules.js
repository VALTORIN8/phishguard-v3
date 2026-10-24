// Shared test helper: load rules.js (and optionally background.js) into an isolated VM context.
const fs = require('fs'), vm = require('vm'), path = require('path');
const EXT = path.resolve(__dirname, '../phishguard-extension');

function noopChrome() {
  const ev = {addListener() {}};
  return {
    tabs: {onUpdated: ev, onActivated: ev, onRemoved: ev, sendMessage: async () => {}, get: async () => ({}), query: async () => [], update: async () => ({})},
    action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}},
    runtime: {onMessage: ev, getURL: p => 'chrome-extension://test/' + p},
    storage: {local: {get: async () => ({})}, onChanged: ev}
  };
}
function loadExtension({chrome = noopChrome(), background = false} = {}) {
  const ctx = vm.createContext({chrome, URL, URLSearchParams, console, Set, Map, Promise, setTimeout, clearTimeout});
  vm.runInContext(fs.readFileSync(path.join(EXT, 'rules.js'), 'utf8'), ctx, {filename: 'rules.js'});
  if (background) vm.runInContext(fs.readFileSync(path.join(EXT, 'background.js'), 'utf8'), ctx, {filename: 'background.js'});
  return {ctx, rules: ctx.PhishGuardRules};
}
module.exports = {EXT, loadExtension, noopChrome};
