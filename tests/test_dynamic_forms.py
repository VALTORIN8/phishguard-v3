"""Forms added after load, and how much work busy pages cause."""
from playwright.sync_api import sync_playwright
from pg_harness import new_context, open_page, sent

TICK = '<div id="feed"></div><script>setInterval(()=>{const d=document.createElement("div");d.textContent=Date.now();document.getElementById("feed").prepend(d)},100)</script>'
PAGES = {
    'www.dynamic-example.com': '<h1>Dynamic sign-in</h1><div id="slot"></div>',
    'www.live-feed-example.com': '<h1>Live</h1>' + TICK,
    'www.live-login-example.com': '<h1>Sign in</h1><form action="/login"><input type="password"></form><div id="later"></div>' + TICK,
}

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = new_context(browser, PAGES)

    # 1. A password form injected after load is scanned, warned about and never has its value read.
    page, errors = open_page(ctx, 'https://www.dynamic-example.com/')
    page.wait_for_function("window.__sent.some(m => m.type === 'PAGE_SCAN_UPDATE')")
    assert sent(page, 'PAGE_SCAN_UPDATE')[-1]['page']['hasPassword'] is False
    page.evaluate('''document.querySelector('#slot').innerHTML='<h2>Account suspended</h2><p>Verify immediately</p><form action="http://bad.example.net/credentials"><input type="password" value="DONT_READ_THIS_PASSWORD"><button type="submit">Sign in</button></form>';''')
    page.wait_for_function("window.__sent.some(m => m.type === 'PAGE_SCAN_UPDATE' && m.page.hasPassword && m.page.signals.some(s => s.id === 'insecure-action'))", timeout=5000)
    page.wait_for_function('document.getElementById("pg-banner") !== null', timeout=5000)
    data = sent(page, 'PAGE_SCAN_UPDATE')[-1]['page']
    assert data['destinations'][0]['host'] == 'bad.example.net'
    assert 'DONT_READ_THIS_PASSWORD' not in str(page.evaluate('window.__sent'))
    assert 'ext' in [s['id'] for s in data['signals']] and 'urg' in [s['id'] for s in data['signals']]
    page.evaluate("window.__deliver({type:'PROTECTION_CHANGED',enabled:false})")
    page.wait_for_function('document.getElementById("pg-banner") == null')
    page.evaluate("window.__deliver({type:'PROTECTION_CHANGED',enabled:true})")
    page.wait_for_function('document.getElementById("pg-banner") !== null')
    assert not errors, errors
    page.close()

    # 2. A page that changes 10x per second with no login form: no rescans and no messages.
    page, errors = open_page(ctx, 'https://www.live-feed-example.com/', settle_ms=1000)
    page.evaluate('window.__pwQueries = 0; window.__sent = []')
    page.wait_for_timeout(5000)
    scans, msgs = page.evaluate('window.__pwQueries'), len(page.evaluate('window.__sent'))
    assert scans == 0 and msgs == 0, f'busy page without password: {scans} scans, {msgs} messages in 5 s'
    assert not errors, errors
    page.close()

    # 3. Busy sign-in page: rescans are throttled to about one every 3 s, and late urgency text is still caught.
    page, errors = open_page(ctx, 'https://www.live-login-example.com/', settle_ms=1000)
    page.evaluate('window.__pwQueries = 0; window.__sent = []')
    page.wait_for_timeout(6500)
    scans = page.evaluate('window.__pwQueries')
    assert 1 <= scans <= 3, f'busy sign-in page rescanned {scans} times in 6.5 s'
    assert len(sent(page, 'PAGE_SCAN_UPDATE')) == 0, 'unchanged evidence must not be re-sent'
    page.evaluate('''document.getElementById('later').textContent = 'Account suspended - verify immediately';''')
    page.wait_for_function("window.__sent.some(m => m.type === 'PAGE_SCAN_UPDATE' && m.page.signals.some(s => s.id === 'urg'))", timeout=4500)
    assert not errors, errors
    page.close()

    browser.close()
    print(f'PASS dynamic forms: late password form scanned, value never sent, banner + global OFF/ON; '
          f'busy page 0 scans/0 messages in 5 s; busy sign-in page {scans} scans in 6.5 s and late urgency text detected')
