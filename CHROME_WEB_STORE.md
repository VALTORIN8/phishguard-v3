# Chrome Web Store submission notes — PhishGuard 3.5.1

Text to paste into the Developer Dashboard, plus a checklist. Review the current wording of each form field before submitting; Google changes the dashboard from time to time.

## Package

Zip the **contents of `phishguard-extension/`** (so `manifest.json` is at the top of the zip). Do not include `tests/`, this file, or `TEST_RESULTS.md`.

## Store listing

- **Name:** PhishGuard — Phishing Shield
- **Category:** Privacy & Security (or the closest security category offered)
- **Short description (from manifest):** On-device phishing clues, live page scanning, password destination checks, independent protection and trusted-site controls.
- Avoid words like "AI", "guaranteed", "blocks all phishing" or "real-time threat database". PhishGuard is a local, rule-based warning tool.
- **Screenshots:** 1280×800 or 640×400. Good choices: the popup Overview, the Analysis tab, the in-page warning, and the "You left a page PhishGuard flagged" page.
- **Icon:** `icons/icon128.png` (128×128). Make sure you have the right to use the shield artwork if it came from an icon site.

## Privacy practices tab

**Single purpose**

> PhishGuard warns users about phishing warning signs on the websites they visit, using on-device checks of the page address and its sign-in forms.

**Permission justifications**

- **Host permission `<all_urls>`:** PhishGuard checks every HTTP(S) page the user opens for phishing warning signs: the page address, whether it has a password field, and where its sign-in form declares it will send data. It shows a warning on high-risk pages and a hover preview for links. These checks must run on any site because phishing pages can be on any domain. All processing is on-device; nothing is transmitted.
- **`storage`:** Saves the user's on/off setting, the hostnames they chose to trust, and a local scan history (up to 25 entries) in `chrome.storage.local`. Nothing is synced or sent anywhere.
- **`scripting`:** After install or update, injects PhishGuard's own bundled content script into tabs that were already open, so those tabs can be checked without reloading. Only packaged files are injected.

**Remote code:** No. All JavaScript is included in the package; nothing is downloaded or evaluated at run time.

**Data usage**

PhishGuard reads page addresses and page structure (website content) on the device and keeps a short local scan history of hostnames (web history). None of it leaves the device. Depending on how the current form defines "collect", either:

- tick nothing (no data is collected or transmitted), or, to be conservative,
- tick **Web history** and **Website content** and state that they are processed only on the device and never transmitted.

Then certify the three statements: not sold to third parties, not used for unrelated purposes, not used for creditworthiness or lending.

**Privacy policy URL:** publish `PRIVACY_POLICY.md` on a public page (for example GitHub Pages or Google Sites) and paste that link. The dashboard needs a public URL, not a file.

## Before you submit

- [ ] Load `phishguard-extension/` with **Load unpacked** in your own Chrome and click through: a normal site, a bank site, the URL Scanner, Settings, History.
- [ ] Run `python3 tests/run_all.py`.
- [ ] Confirm the contact address in `popup.js` (`CONTACT_EMAIL`) and in the privacy policy is the one you want users to write to.
- [ ] Optional but useful: run `node tests/evaluate_uci_csv.js` on the PhiUSIIL dataset and keep the numbers for your own records.
- [ ] Expect a longer review because of `<all_urls>`; the justification above explains why it is needed.
