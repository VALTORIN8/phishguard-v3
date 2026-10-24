"""Content-script behaviour on routed pages (mocked chrome API, real Chromium DOM)."""
from playwright.sync_api import sync_playwright
from pg_harness import new_context, open_page, sent

PHISH = '''<h1>Account suspended</h1><p>Verify immediately. Confirm your identity or account will be blocked.</p>
<form method="post" action="http://collect.example.net/password"><input name="u"><input id="pw" type="password" value="supersecret"><button>Log in</button></form>
<a href="https://paypa1-secure.xyz/login">Visit support</a>'''
PAGES = {
    'paypa1-secure.xyz': PHISH,
    'collect.example.net': '<h1>collected</h1>',
    'finance.yahoo.com': '<h1>Markets</h1><p>Sensex, Nifty, stock quotes.</p>',
    'netbanking.hdfc.bank.in': '<h1>NetBanking</h1><form action="/login" method="post"><input name="u"><input id="pw" type="password"><button>Login</button></form>',
    'www.shop-example.com': '<form action="https://login.shop-example.com/session" method="post"><input type="password"><button>Sign in</button></form>',
    'www.js-form-example.com': '<form action="javascript:void(0)"><input type="password"><button>Sign in</button></form>',
    'www.http-post-example.com': '<form action="http://www.http-post-example.com/login" method="post"><input type="password"><button>Sign in</button></form>',
    'localhost': '<form action="/login" method="post"><input type="password"><button>Sign in</button></form>',
}


def signal_ids(page):
    return {s['id'] for s in page.evaluate("window.__deliver({type:'SCAN_DOM'})")['signals']}


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = new_context(browser, PAGES)
    all_errors = []

    # 1. Phishing-style page: detection, privacy, banner, password guard that can be passed.
    page, errors = open_page(ctx, 'https://paypa1-secure.xyz/login')
    all_errors += errors
    page.wait_for_function('document.getElementById("pg-banner") !== null')
    result = page.evaluate("window.__deliver({type:'SCAN_DOM'})")
    assert result['ok'] and len(result['checked']) == 3
    assert {s['id'] for s in result['signals']} >= {'insecure-action', 'ext', 'urg'}
    assert 'supersecret' not in str(result) and 'supersecret' not in str(page.evaluate('window.__sent'))
    pw = page.locator('#pw')
    pw.click()
    page.wait_for_function('document.getElementById("pg-guardian") !== null')
    assert page.locator('#pg-guardian .pg-g-safe').inner_text() == 'Back to safety'
    page.locator('#pg-guardian .pg-g-risk').click()
    assert page.locator('#pg-guardian').count() == 0
    page.keyboard.type('abc')
    assert len(pw.input_value()) == len('supersecret') + 3, 'user who chose to continue must be able to type'
    pw.evaluate('e => e.blur()'); pw.click(); page.wait_for_timeout(250)
    assert page.locator('#pg-guardian').count() == 0, 'guard must not reappear after the user chose to continue'
    # Trust toggling hides and restores the banner without a reload.
    page.evaluate("window.__deliver({type:'TOGGLE_SITE',disabled:true})")
    assert page.locator('#pg-banner').count() == 0
    page.evaluate("window.__deliver({type:'TOGGLE_SITE',disabled:false})")
    page.wait_for_function('document.getElementById("pg-banner") !== null')
    # CLEAR_WARNING from a worker without page evidence must not remove a warning the page still justifies.
    page.evaluate("window.__deliver({type:'CLEAR_WARNING',suppressed:false})")
    page.wait_for_timeout(100)
    assert page.locator('#pg-banner').count() == 1
    page.locator('#pg-banner .pg-ban-back').click()
    assert len(sent(page, 'LEAVE_PAGE')) == 1, 'Back to safety asks the worker to leave the page'
    page.close()

    # 2. Submit guard: Continue anyway really submits.
    page, errors = open_page(ctx, 'https://paypa1-secure.xyz/login')
    all_errors += errors
    page.evaluate("document.querySelector('form').requestSubmit()")
    page.wait_for_function('document.getElementById("pg-guardian") !== null')
    with page.expect_navigation():
        page.locator('#pg-guardian .pg-g-risk').click()
    assert 'collect.example.net' in page.url
    page.close()

    # 3. Real bank and ordinary sites stay quiet; typing works.
    page, errors = open_page(ctx, 'https://netbanking.hdfc.bank.in/login')
    all_errors += errors
    page.locator('#pw').click(); page.wait_for_timeout(250)
    assert page.locator('#pg-guardian').count() == 0 and page.locator('#pg-banner').count() == 0
    page.keyboard.type('abc'); assert page.locator('#pw').input_value() == 'abc'
    assert signal_ids(page) == set()
    page.close()

    page, errors = open_page(ctx, 'https://finance.yahoo.com/')
    all_errors += errors
    assert page.locator('#pg-banner').count() == 0
    page.close()

    # 4. Sibling-subdomain login is the same website, not "external".
    page, errors = open_page(ctx, 'https://www.shop-example.com/')
    all_errors += errors
    dom = page.evaluate("window.__deliver({type:'SCAN_DOM'})")
    assert dom['destinations'][0]['relation'] == 'same-site' and not dom['signals'], dom
    page.close()

    # 5. javascript: form actions are "handled by page script", not insecure or external.
    page, errors = open_page(ctx, 'https://www.js-form-example.com/')
    all_errors += errors
    dom = page.evaluate("window.__deliver({type:'SCAN_DOM'})")
    assert dom['destinations'][0]['protocol'] == 'script:' and not dom['signals'], dom
    assert page.locator('#pg-banner').count() == 0
    page.close()

    # 6. Exactly 55 (HTTPS page posting a password to HTTP) is high risk on the page too.
    page, errors = open_page(ctx, 'https://www.http-post-example.com/')
    all_errors += errors
    assert signal_ids(page) == {'insecure-action'}
    page.wait_for_function('document.getElementById("pg-banner") !== null')
    page.close()

    # 7. Local development over http://localhost is not treated as an unencrypted login.
    page, errors = open_page(ctx, 'http://localhost:3000/login')
    all_errors += errors
    assert signal_ids(page) == set() and page.locator('#pg-banner').count() == 0
    page.close()

    assert not all_errors, all_errors
    browser.close()
    print('PASS content: phishing signals, no password values captured, banner, guard passable with Continue anyway, '
          'submit guard continues, Back to safety, bank.in quiet, sibling subdomain same-site, javascript: actions, '
          'score 55 banner, localhost quiet, trust toggle, CLEAR_WARNING race')
