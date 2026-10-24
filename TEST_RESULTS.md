# PhishGuard v3.5.1 — test results

Run date: 2026-10-24. Chromium via Playwright 1.63 (new headless mode), Node 22, Python 3.13, Linux.
Command: `python3 tests/run_all.py` → **11/11 passed**.

## Real install in Chromium (new in 3.5.1)

`tests/test_real_chromium.py` loads the unpacked extension into Chromium: the real service worker, content scripts, toolbar badges, popup page and safe page all run. Websites are answered locally by request routing, so nothing on the internet is contacted.

| Page | v3.5 | v3.5.1 |
| --- | --- | --- |
| `finance.yahoo.com` | **!** badge + red banner | ✓, no banner |
| `sbi.bank.in` | **!** badge + red banner | ✓, no banner |
| `netbanking.hdfc.bank.in` login | **!**, password field could not be typed in (0 characters) | ✓, no warning, typing works |
| `www.shop-example.com` posting to `login.shop-example.com` | **?** (sibling subdomain called external) | ✓ |
| Form with `action="javascript:void(0)"` | **!** + banner (score 83) | ✓ |
| `paypa1-secure.xyz` phishing-style login | **!**, banner; "Dismiss" re-opened on every click, 0 characters typed; "Go back" relied on `history.back()`, which does nothing in a tab opened from a link | **!**, banner, guard shown once; "Continue anyway" lets the user type; "Back to safety" opens PhishGuard's safe page |
| Page adding content twice a second | 20 messages to the service worker in 10 s | 0 messages |
| Popup page under the real extension CSP | — | shared rules load; `icici.bank.in` low, `onlinesbi-kyc.in` high |
| Manifest | `tabs` permission requested | `tabs` removed; badge and tab URLs still work |

## Automated checks

| Test | Result | What it covers |
| --- | --- | --- |
| Syntax | PASS | `node --check` on all five extension scripts |
| `check_urls.js` | PASS | 52 legitimate URLs stay below 26, 30 phishing-style URLs score 55+, 2 more score 26+, 4 invalid inputs rejected, 7 domain splits, Punycode decoder checked against Python's codec |
| `test_background.js` | PASS | Badges ✓ / ? / ! / OFF / T / …, score 55 is "!", script-handled destinations, `.bank.in` clean, "Back to safety" navigation, stale-update rejection |
| `check_content.py` | PASS | Phishing signals, password values never captured or sent, banner, guard passable, submit guard continues, "Back to safety", bank login quiet, sibling subdomain same-site, `javascript:` actions, score-55 banner, `localhost` quiet, trust toggle, warning not cleared by a worker without page evidence |
| `test_dynamic_forms.py` | PASS | Late-added password form, global OFF/ON; busy page: 0 rescans and 0 messages in 5 s; busy sign-in page: 2 rescans in 6.5 s and late urgency text still detected |
| `test_popup.py` | PASS | Scanning state, 8/8 coverage, no overflow, switch vs trust independence, destination labels, report, contact, local URL scanner, 3 permission cards, history, dialogs, 55 = HIGH RISK |
| `test_real_chromium.py` | PASS | Table above |

### Same URL lists, old vs new rules

On the URL lists in `tests/check_urls.js` (52 legitimate, 32 phishing-style):

| | v3.5 | v3.5.1 |
| --- | --- | --- |
| Legitimate URLs flagged (score 26+) | 32 of 52 (31 as HIGH RISK) | 0 |
| Phishing-style URLs missed (score under 26) | 12 of 32 | 0 |

These lists were written to cover the problems fixed in this release, so this is a regression check, not an accuracy estimate.

## Not tested or not proven

- **PhiUSIIL benchmark:** the dataset site could not be reached from the build environment. Run `node tests/evaluate_uci_csv.js <csv>` to get URL-only precision, recall and false-positive rate. No benchmark numbers are claimed.
- **Google Chrome on Windows/macOS:** the install test used Chromium on Linux. Load the folder in your own Chrome and click through once before publishing.
- The official-domain list is hand-maintained. A brand's new domain that isn't listed gets a small "unlisted domain" note (8 points), not a warning, unless it uses an often-abused ending.
- The password destination inspector reads HTML-declared form URLs; JavaScript can submit elsewhere. No network interception or credential capture.
- This is not verified real-time threat intelligence, a network blocker, or a guaranteed phishing classification.
