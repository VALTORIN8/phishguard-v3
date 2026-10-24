"""Shared helpers for the Playwright page tests.

Pages are served by request routing (no network, no local server): every URL is answered from a
dict of HTML strings, and the content script runs at document start with a mocked `chrome` API.
"""
from pathlib import Path
from urllib.parse import urlparse

EXT = Path(__file__).resolve().parent.parent / 'phishguard-extension'
OUT = Path(__file__).resolve().parent / 'output'

CHROME_MOCK = r'''
(() => {
  window.__sent = []; window.__listeners = []; window.__pwQueries = 0;
  window.__store = Object.assign({whitelist: [], protectionEnabled: true}, window.__initialStore || {});
  const q = Document.prototype.querySelector;
  Document.prototype.querySelector = function (s) { if (s === 'input[type="password"]') window.__pwQueries++; return q.call(this, s); };
  window.chrome = {
    runtime: {
      lastError: null,
      onMessage: {addListener: f => window.__listeners.push(f)},
      sendMessage: m => { window.__sent.push(JSON.parse(JSON.stringify(m))); return Promise.resolve({ok: true}); }
    },
    storage: {local: {get: async () => ({...window.__store})}, onChanged: {addListener: () => {}}}
  };
  window.__deliver = msg => { let out; for (const f of window.__listeners) f(msg, null, r => { out = r; }); return out; };
})();
'''


def init_script():
    return CHROME_MOCK + '\n' + (EXT / 'rules.js').read_text(encoding='utf-8') + '\n' + (EXT / 'content.js').read_text(encoding='utf-8')


def new_context(browser, pages):
    """pages: {hostname: html_body}. Unknown hosts get a blank page."""
    ctx = browser.new_context()
    css = (EXT / 'content.css').read_text(encoding='utf-8')

    def handle(route):
        host = urlparse(route.request.url).hostname or ''
        body = pages.get(host, '<h1>ok</h1>')
        html = f'<!doctype html><html><head><title>{host}</title><style>{css}</style></head><body>{body}</body></html>'
        route.fulfill(status=200, content_type='text/html', body=html)

    ctx.route('**/*', handle)
    ctx.add_init_script(init_script())
    return ctx


def open_page(ctx, url, settle_ms=900):
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(url)
    page.wait_for_timeout(settle_ms)
    return page, errors


def sent(page, kind):
    return page.evaluate('k => window.__sent.filter(m => m.type === k)', kind)
