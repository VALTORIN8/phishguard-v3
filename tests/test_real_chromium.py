"""Real-install test: loads the unpacked extension into Chromium (service worker, content scripts,
badges, popup page and safe page all real). Websites are answered by request routing, so nothing on
the internet is contacted. Needs Playwright 1.49+ (extensions in the new headless mode)."""
import json, re, tempfile
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
from pg_harness import EXT, OUT

TICK = '<div id="c"></div><script>setInterval(()=>{const d=document.createElement("div");d.textContent=Date.now();document.getElementById("c").prepend(d)},500)</script>'
PAGES = {
    'finance.yahoo.com': '<h1>Markets</h1><p>Sensex, Nifty, stock quotes.</p>',
    'sbi.bank.in': '<h1>State Bank of India</h1>',
    'netbanking.hdfc.bank.in': '<h1>NetBanking</h1><form action="/login" method="post"><input name="u"><input id="pw" type="password"><button>Login</button></form>',
    'www.shop-example.com': '<form action="https://login.shop-example.com/session" method="post"><input type="password"><button>Sign in</button></form>',
    'www.js-form-example.com': '<form action="javascript:void(0)"><input type="password"><button>Sign in</button></form>',
    'paypa1-secure.xyz': '<h1>Account suspended</h1><p>Verify immediately.</p><form action="/collect" method="post"><input name="u"><input id="pw" type="password"><button>Log in</button></form>',
    'www.live-feed-example.com': '<h1>Live</h1>' + TICK,
}


def fulfill(route):
    host = urlparse(route.request.url).hostname or ''
    route.fulfill(status=200, content_type='text/html', body=f'<!doctype html><title>{host}</title>{PAGES.get(host, "<h1>ok</h1>")}')


results = {}
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(tempfile.mkdtemp(), channel='chromium', headless=True,
        args=[f'--disable-extensions-except={EXT}', f'--load-extension={EXT}'])
    ctx.route(re.compile(r'^https?://'), fulfill)  # websites only; extension files load for real
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event('serviceworker', timeout=15000)
    ext_id = sw.url.split('/')[2]
    assert sw.evaluate('() => typeof PhishGuardRules') == 'object', 'rules.js not loaded in service worker'
    perms = sw.evaluate('() => chrome.runtime.getManifest().permissions')
    assert 'tabs' not in perms, perms
    sw.evaluate("() => { self.__msgs = {}; chrome.runtime.onMessage.addListener(m => { self.__msgs[m?.type] = (self.__msgs[m?.type] || 0) + 1; }); }")
    badge = lambda url: sw.evaluate("async u => { const [t] = await chrome.tabs.query({url: u}); return t ? chrome.action.getBadgeText({tabId: t.id}) : null; }", url)

    def visit(host, path='/'):
        page = ctx.new_page()
        errs = []; page.on('pageerror', lambda e: errs.append(str(e)))
        url = f'https://{host}{path}'
        page.goto(url); page.wait_for_timeout(1800)
        return page, url, errs

    # Legitimate sites that v3.5 flagged: badge ✓, no banner.
    for host in ['finance.yahoo.com', 'sbi.bank.in', 'www.shop-example.com', 'www.js-form-example.com']:
        page, url, errs = visit(host)
        results[host] = {'badge': badge(url), 'banner': page.locator('#pg-banner').count()}
        assert results[host] == {'badge': '✓', 'banner': 0}, (host, results[host])
        assert not errs, errs
        page.close()

    # Real HDFC login: no warning, password can be typed.
    page, url, errs = visit('netbanking.hdfc.bank.in', '/login')
    page.locator('#pw').click(); page.wait_for_timeout(300)
    assert page.locator('#pg-guardian').count() == 0
    page.keyboard.type('abc')
    results['netbanking.hdfc.bank.in'] = {'badge': badge(url), 'typed': len(page.locator('#pw').input_value())}
    assert results['netbanking.hdfc.bank.in'] == {'badge': '✓', 'typed': 3}, results['netbanking.hdfc.bank.in']
    page.close()

    # Phishing page: badge !, banner, guard can be passed, Back to safety leaves even with no history.
    page, url, errs = visit('paypa1-secure.xyz', '/login')
    r = {'badge': badge(url), 'banner': page.locator('#pg-banner').count()}
    pw = page.locator('#pw')
    pw.click(); page.wait_for_timeout(300)
    r['guard_on_focus'] = page.locator('#pg-guardian').count()
    page.locator('#pg-guardian .pg-g-risk').click(); page.wait_for_timeout(200)
    page.keyboard.type('abc')
    pw.evaluate('e => e.blur()'); pw.click(); page.wait_for_timeout(300)
    r['guard_after_continue'] = page.locator('#pg-guardian').count()
    r['typed'] = len(pw.input_value())
    page.locator('#pg-banner .pg-ban-back').click()
    page.wait_for_url(f'chrome-extension://{ext_id}/safe.html*', timeout=5000)
    page.wait_for_timeout(300)
    r['after_back_to_safety'] = page.url.split('?')[0].replace(ext_id, '<id>')
    r['safe_page_site'] = page.locator('#site').inner_text()
    results['paypa1-secure.xyz'] = r
    assert r == {'badge': '!', 'banner': 1, 'guard_on_focus': 1, 'guard_after_continue': 0, 'typed': 3,
                 'after_back_to_safety': 'chrome-extension://<id>/safe.html', 'safe_page_site': 'paypa1-secure.xyz'}, r
    page.close()

    # Busy page: messages reaching the service worker in 10 s.
    page, url, errs = visit('www.live-feed-example.com')
    sw.evaluate('() => { self.__msgs = {}; }')
    page.wait_for_timeout(10000)
    msgs = sw.evaluate('() => self.__msgs')
    results['www.live-feed-example.com'] = {'badge': badge(url), 'worker_messages_in_10s': sum(msgs.values())}
    assert sum(msgs.values()) <= 1, msgs
    page.close()

    # Popup page loads the shared rules under the extension's real CSP.
    page = ctx.new_page(); errs = []; page.on('pageerror', lambda e: errs.append(str(e)))
    page.goto(f'chrome-extension://{ext_id}/popup.html'); page.wait_for_timeout(800)
    page.locator('[data-view="scanner"]').click()
    page.locator('#manualUrl').fill('https://www.icici.bank.in/'); page.locator('#btnScan').click()
    low = 'LOW URL RISK' in page.locator('#manualOut').inner_text()
    page.locator('#manualUrl').fill('https://onlinesbi-kyc.in/'); page.locator('#btnScan').click()
    high = 'HIGH RISK' in page.locator('#manualOut').inner_text()
    results['popup'] = {'icici.bank.in low': low, 'onlinesbi-kyc.in high': high, 'errors': errs}
    assert low and high and not errs, results['popup']
    OUT.mkdir(exist_ok=True)
    page.close()
    ctx.close()

print(json.dumps(results, indent=2, ensure_ascii=False))
print('PASS real Chromium install: extension loaded unpacked; badges, banner, password guard, Back to safety, busy-page traffic and popup verified')
