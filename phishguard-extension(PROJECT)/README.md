# PhishGuard v3.5.1 — real-time local phishing clues

Manifest V3 Chrome extension. No npm install, build step, remote threat-service API, or account required.

## What changed in 3.5.1

- **Real bank and brand sites are no longer flagged.** `sbi.bank.in`, `hdfc.bank.in`, `icici.bank.in` (RBI's `.bank.in` move), Google/Amazon country sites (`google.es`, `amazon.ae`), brand-owned endings (`blog.google`) and alternate official domains (`paypal.me`, `amazon.jobs`, `binance.us`) are recognized.
- **Ordinary words are no longer "lookalikes".** `finance.yahoo.com` (≈ binance), `apply.*` (≈ apple), `team.*`/`stream.*` (≈ steam) and `paypay.ne.jp` stay low. One-letter typos are only checked for long brand names, minus real dictionary words.
- **The password warning can be passed.** "Continue anyway" now sticks for that page, so a user who decides to proceed can type. The safer default button is focused.
- **`action="javascript:…"` forms** are shown as "handled by the page's JavaScript" instead of insecure + external.
- **More phishing caught:** official domains used as a subdomain (`login.microsoftonline.com.verify-session.ru`), brand names on free hosting (`amazon-signin.s3.amazonaws.com`, `*.github.io`, `*.netlify.app`…), brand aliases (`onlinesbi-kyc.in`, `appleid-verify.com`, `yonosbi-…`), typo-squats of long names (`steamcommunuty.com`) and look-alike letters from other alphabets (IDN homographs such as `xn--80ak6aa92e.com` → "аррӏе").
- **Same website, different subdomain** (`www.x.com` → `login.x.com`) is recognized as the same site.
- **One threshold everywhere:** 55+ is high risk in the badge, popup, banner and password guard; 26–54 is review.
- **"Back to safety"** replaces the flagged page with PhishGuard's own page, so it works even when the link opened in a new tab with no history.
- **Busy pages are cheap:** URL rules run locally in the page, and rescans happen only when forms/inputs change (at most every 3 s on sign-in pages for other changes).
- **`tabs` permission removed** (host access already covers it). Icons are now exact 16/32/48/128 px.
- Rule-based scoring is named `urlScore` (was `aiScore`); shared by the worker, page and popup via `rules.js`.

## Install / update

1. Unzip the package.
2. In Chrome visit `chrome://extensions/`, enable **Developer mode**, and select **Load unpacked**.
3. Select the `phishguard-extension` folder containing `manifest.json`.
4. If updating the **same** installed extension directory, replace files and click **Reload** instead to retain its Chrome local storage. Removing/reinstalling can lose stored history and trust preferences.
5. Refresh any previously open HTTP(S) sites after installation and click the PhishGuard toolbar icon.

The popup always begins with a blue animated **SCANNING…** indicator and a fresh local scan, not a cached verdict. Use **↻ Rescan** to repeat the scan without closing the popup. When page inspection is restricted, coverage explicitly falls back to URL-only (5/8 checks).

## Global protection vs trusted sites

- The **On/Off switch** enables or pauses local warnings **globally**; it does not modify any trusted sites.
- **Trust this site** suppresses warnings only on the **exact current hostname**. Scans remain visible, and the toolbar badge shows **T** when trusted.
- Add/remove hostnames separately from **Settings → Trusted sites**. Trust is not a security endorsement.
- The toolbar badge displays **✓** after full low-risk checks, **…** for URL-only/partial, **?** for review (26–54), **!** for high risk (55+), **OFF** if globally paused, and **T** if trusted. A checkmark means no rules triggered in completed checks, *not* a guarantee of safety.

## Features and limitations

- Risk score is an explainable, bounded *heuristic* suspicion score, **not** a probability of phishing.
- Evidence quality is described as **URL-only**, **Broader scan**, or **Combined clues**. These are not calibrated accuracy or confidence scores.
- Coverage reports completion of eight local checks. Even 8/8 **does not** prove a website is safe.
- Inspects suspicious URL patterns, commonly impersonated brands (with an official-domain list per brand), TLS scheme, declared HTML password-form destinations, and sign-in pressure phrases. High-risk pages get a badge, warning banner, and password-form warning. Users can choose to continue. PhishGuard does not block network requests or provide a live threat reputation database.
- A brand name on a domain that is not on the list (for example a new country site) gets a small "unlisted domain" note rather than a high-risk warning. Brand names on cheap, often-abused endings (`.xyz`, `.top`, …) are still high risk.
- Analysis displays password-form destinations as **declared form endpoints**, never actual captured network traffic. JavaScript-handled submissions can use different URLs and may not be detectable; shadow DOM, cross-origin frames, and restricted Chrome pages may also be inaccessible.
- Does not read or transmit input/password values, submit form data, or send scanned URLs to a PhishGuard server. Contact Developer opens a prepared mail draft only on user action.

## Permissions and privacy

- `<all_urls>` host access and a content script: the page-local checks run on ordinary HTTP(S) webpages. Host access also lets the extension read the current tab's address for its badge, so the separate `tabs` permission is not requested.
- `storage`: history, preferences and exact hostname trusts, on this device only.
- `scripting`: reconnects scans after installation/reload on tabs that were already open.

No third-party analytics, remote model, remote list downloads, or sensitive input value capture. See `PRIVACY_POLICY.md` and `CHROME_WEB_STORE.md` (in the package root) before publishing.

## Tests

From the folder containing `phishguard-extension` and `tests`, with Node 18+ and Python 3 + Playwright 1.49+ (`pip install playwright && playwright install chromium`):

```bash
python3 tests/run_all.py                    # all tests, including a real install in Chromium
python3 tests/run_all.py --skip-real-browser
```

Individual tests: `node tests/check_urls.js`, `node tests/test_background.js`, `python3 tests/check_content.py`, `python3 tests/test_dynamic_forms.py`, `python3 tests/test_popup.py`, `python3 tests/test_real_chromium.py`. Websites in the browser tests are answered locally by request routing; nothing on the internet is visited.

### Reproducible real labeled dataset evaluation

Download the published **[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)** (UCI, Prasad and Chandra, 2024). Its published labels are `0 = phishing` and `1 = legitimate`. Run **without visiting any suspicious URLs**:

```bash
node tests/evaluate_uci_csv.js ~/Downloads/PhiUSIIL_Phishing_URL_Dataset.csv
```

The script computes URL-only precision, recall and false-positive rate on a deterministic balanced sample of up to 1,000 per class. Dataset labels are historical and may be imperfect or stale; it cannot validate the live page scanner. The dataset is **not bundled**, and **no PhiUSIIL benchmark results are claimed** yet.
