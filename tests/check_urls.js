// URL-rule regression tests. No URL is fetched or opened.
const assert = require('assert');
const {loadExtension} = require('./load_rules');
const {rules: R} = loadExtension({background: true}); // also proves background.js loads on top of rules.js
const scan = url => R.urlScore(url);
const fails = [];
const check = (cond, msg) => {if (!cond) fails.push(msg);};

// Official or ordinary sites: must stay LOW (score < 26). Several were HIGH RISK in v3.5.
const legit = [
  // v3.5 cases
  'https://fast.com/', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'https://www.amazon.in/', 'https://www.paypal.com/signin',
  'https://login.microsoftonline.com/', 'https://accounts.google.com/signin/v2', 'https://github.com/login', 'https://s3.amazonaws.com/',
  'https://www.flipkart.com/',
  // Indian banks moved to .bank.in (RBI deadline 31 Oct 2025)
  'https://sbi.bank.in/', 'https://www.hdfc.bank.in/', 'https://netbanking.hdfc.bank.in/login', 'https://www.icici.bank.in/',
  'https://retail.onlinesbi.sbi/retail/login.htm', 'https://www.hdfc.com/',
  // Brand country domains, brand-owned endings and alternate official domains
  'https://www.google.es/', 'https://www.google.co.id/', 'https://www.google.com.sg/', 'https://www.google.ae/', 'https://www.google.com.pk/',
  'https://blog.google/', 'https://about.google/', 'https://www.amazon.ae/', 'https://www.amazon.sg/', 'https://www.amazon.nl/',
  'https://www.amazon.com.mx/', 'https://www.amazon.co.za/', 'https://www.amazon.jobs/', 'https://www.amazon.science/',
  'https://www.paypal.me/someone', 'https://www.binance.us/', 'https://apple.co/3abc', 'https://discord.gift/abc',
  'https://store.steampowered.com/', 'https://steamcommunity.com/login', 'https://web.whatsapp.com/', 'https://www.netflix.com/in/login',
  // Brand-named project pages on shared hosting (low note only)
  'https://google.github.io/styleguide/', 'https://microsoft.github.io/monaco-editor/', 'https://discord.js.org/',
  // Ordinary words one letter away from a brand
  'https://finance.yahoo.com/', 'https://apply.workable.com/acme/', 'https://team.example.com/', 'https://stream.example.com/',
  'https://www.paypay.ne.jp/', 'https://amazonas.am.gov.br/',
  // Local development is not "unencrypted website"
  'http://localhost:3000/login', 'http://127.0.0.1:8080/',
  // Other everyday Indian sites
  'https://accounts.zoho.in/signin', 'https://www.irctc.co.in/nget/train-search', 'https://paytm.com/', 'https://www.phonepe.com/'
];
// Phishing-style addresses: must be at least REVIEW (>= 26); the first group must be HIGH (>= 55).
const high = [
  'https://paypa1-secure.xyz/login', 'https://amaz0n-secure-login.xyz/verify', 'https://paypal.com.account-review.example.net/login',
  'https://amazon-update-account.example.org/verify', 'https://micros0ft-auth.example.net/confirm', 'https://login-google.example.net/verify',
  'https://github-support.example.net/login', 'http://paypal-login.example.org/verify-account', 'https://google.com@security.example.net/login',
  'https://paypal.com.evil.test',
  // Missed by v3.5 (scored 0)
  'https://login.microsoftonline.com.verify-session.ru/', 'https://amazon-signin.s3.amazonaws.com/login.html',
  'https://onlinesbi-kyc.in/', 'https://appleid-verify.com/',
  // More Indian banking and typo-squat patterns
  'https://sbi-kyc-update.netlify.app/verify', 'https://hdfc-netbanking-verify.vercel.app/', 'https://icici-reward-points.co.in/claim',
  'https://yonosbi-reward.in/', 'https://hdfcbank-kyc.co/', 'https://steamcommunuty.com/tradeoffer', 'https://stearncommunity.com/',
  'https://arnazon.com/', 'https://goog1e.com/', 'https://binanse.com/', 'https://netflixbilling.com/', 'https://discord-nitro-gift.com/',
  'https://amazon.xyz/',
  // Look-alike characters from other alphabets (IDN homographs)
  'https://xn--pypal-4ve.com/', 'https://xn--pple-43d.com/', 'https://xn--80ak6aa92e.com/'
];
const review = ['https://myapp.github.io/paypal.com/verify-password', 'https://secure-login-verify.web.app/account-update'];

for (const url of legit) {
  const r = scan(url);
  check(r.ok && r.score < R.REVIEW_RISK, `legit flagged: ${url} → ${r.score} [${(r.signals || []).map(s => s.id)}]`);
}
for (const url of high) {
  const r = scan(url);
  check(r.ok && r.score >= R.HIGH_RISK, `phishing not HIGH: ${url} → ${r.score} [${(r.signals || []).map(s => s.id)}]`);
}
for (const url of review) {
  const r = scan(url);
  check(r.ok && r.score >= R.REVIEW_RISK, `phishing not flagged: ${url} → ${r.score}`);
}
for (const bad of ['javascript:alert(1)', 'file:///etc/passwd', 'not a url', 'ftp://example.com']) check(!scan(bad).ok, `should reject ${bad}`);

// Domain parsing used for "same website" checks.
const reg = [['login.shop-example.com', 'shop-example.com'], ['netbanking.hdfc.bank.in', 'hdfc.bank.in'], ['www.bbc.co.uk', 'bbc.co.uk'],
  ['a.b.example.com.au', 'example.com.au'], ['myapp.github.io', 'myapp.github.io'], ['x.s3.amazonaws.com', 's3.amazonaws.com'], ['github.io', 'github.io']];
for (const [host, want] of reg) check(R.registrableDomain(host) === want, `registrableDomain(${host}) = ${R.registrableDomain(host)}, want ${want}`);
check(R.sameSite('www.shop-example.com', 'login.shop-example.com'), 'sibling subdomains should be same site');
check(!R.sameSite('alice.github.io', 'bob.github.io'), 'different github.io sites are different sites');
check(!R.sameSite('paypal.com.evil.net', 'paypal.com'), 'embedded domain is not the official site');
// Punycode decoder against Python's codec.
for (const [p, want] of [['pple-43d', 'аpple'], ['pypal-4ve', 'pаypal'], ['mnchen-3ya', 'münchen'], ['80ak6aa92e', 'аррӏе'], ['e1afmkfd', 'пример']]) {
  check(R.punyDecode(p) === want, `punyDecode(${p}) = ${R.punyDecode(p)}`);
}
// Thresholds are shared by every part of the extension.
check(R.HIGH_RISK === 55 && R.REVIEW_RISK === 26, 'thresholds changed unexpectedly');

if (fails.length) {console.error(fails.join('\n')); process.exit(1);}
console.log(`PASS URL rules: ${legit.length} legitimate stay low, ${high.length} phishing-style are high, ${review.length} review, 4 invalid rejected, ${reg.length} domain splits, punycode decoder.`);
console.log('No live URLs visited. Synthetic examples are not verified real-world phishing reports.');
