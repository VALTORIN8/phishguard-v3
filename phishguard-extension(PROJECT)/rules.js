// PhishGuard 3.5.1 — shared, on-device URL rules.
// Loaded by the service worker (importScripts), the content script and the popup.
// Explainable heuristics only: not a reputation service and not a probability of phishing.
globalThis.PhishGuardRules = globalThis.PhishGuardRules || (() => {
  const HIGH_RISK = 55;   // score >= 55 → high risk everywhere (badge, popup, banner, password guard)
  const REVIEW_RISK = 26; // score 26–54 → review

  // domains:  official registrable domains (subdomains included automatically)
  // aliases:  distinctive words that only make sense for this brand (e.g. "onlinesbi")
  // fuzzy:    allow one-letter typos (only for names of 6+ letters, minus real words below)
  // compound: flag the name glued to other words (e.g. "paypalsecure")
  // common:   the name is also an ordinary word, so on its own it is only a medium clue
  // ccTLDs:   brand.<country ending> (google.es, amazon.ae) counts as official
  const BRANDS = {
    amazon: {fuzzy:true, compound:true, common:true, ccTLDs:true, aliases:["amazonpay", "primevideo"], domains:[
      "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca", "amazon.co.jp", "amazon.com.au",
      "amazon.it", "amazon.es", "amazon.com.br", "amazon.com.mx", "amazon.nl", "amazon.sg", "amazon.ae", "amazon.sa",
      "amazon.se", "amazon.pl", "amazon.com.tr", "amazon.com.be", "amazon.eg", "amazon.ie", "amazon.jobs", "amazon.science",
      "amazon.dev", "aboutamazon.com", "amazonpay.in", "amazontrust.com", "media-amazon.com", "ssl-images-amazon.com",
      "primevideo.com", "a2z.com"]},
    paypal: {fuzzy:true, compound:true, ccTLDs:true, domains:["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"]},
    paytm: {aliases:["paytmbank"], domains:["paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com", "paytmmall.com"]},
    sbi: {common:true, aliases:["onlinesbi", "yonosbi", "sbionline"], domains:[
      "sbi.co.in", "sbi.bank.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbigeneral.in"]},
    hdfc: {aliases:["hdfcbank", "hdfcnetbanking"], domains:[
      "hdfcbank.com", "hdfc.bank.in", "hdfcbank.bank.in", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcfund.com", "hdfcsky.com"]},
    icici: {aliases:["icicibank", "icicinetbanking"], domains:[
      "icicibank.com", "icici.bank.in", "icicibank.bank.in", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicipruamc.com", "icicisecurities.com"]},
    google: {fuzzy:true, compound:true, ccTLDs:true, aliases:["gmail"], domains:[
      "google.com", "gmail.com", "youtube.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com",
      "withgoogle.com", "google.dev", "goo.gl", "g.co", "googletagmanager.com", "googlesyndication.com", "googleadservices.com",
      "doubleclick.net", "ggpht.com", "googleblog.com"]},
    microsoft: {fuzzy:true, compound:true, ccTLDs:true, aliases:["microsoftonline", "office365", "microsoft365"], domains:[
      "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoft365.com",
      "azure.com", "bing.com", "msn.com", "xbox.com", "skype.com", "windows.com", "windowsupdate.com", "onenote.com",
      "onedrive.com", "microsoftstore.com", "msft.net", "msauth.net", "msftauth.net", "aka.ms"]},
    apple: {common:true, ccTLDs:true, aliases:["appleid", "icloud", "itunes", "applepay"], domains:[
      "apple.com", "icloud.com", "apple.co", "apple.news", "mzstatic.com", "itunes.com", "icloud-content.com", "apple-cloudkit.com", "cdn-apple.com"]},
    netflix: {fuzzy:true, compound:true, ccTLDs:true, domains:["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net", "fast.com"]},
    facebook: {fuzzy:true, compound:true, ccTLDs:true, domains:["facebook.com", "fb.com", "fb.me", "fbcdn.net", "facebook.net", "meta.com", "messenger.com", "fbsbx.com"]},
    instagram: {fuzzy:true, compound:true, domains:["instagram.com", "cdninstagram.com", "instagr.am"]},
    whatsapp: {fuzzy:true, compound:true, domains:["whatsapp.com", "whatsapp.net", "wa.me"]},
    steam: {common:true, aliases:["steampowered", "steamcommunity"], domains:[
      "steampowered.com", "steamcommunity.com", "steamstatic.com", "steam-chat.com", "steamgames.com", "valvesoftware.com"]},
    discord: {fuzzy:true, compound:true, domains:["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discord.new", "discord.gift"]},
    binance: {fuzzy:true, compound:true, domains:["binance.com", "binance.us", "binance.org", "bnbchain.org"]},
    coinbase: {fuzzy:true, compound:true, domains:["coinbase.com"]},
    flipkart: {fuzzy:true, compound:true, domains:["flipkart.com", "flixcart.com"]},
    phonepe: {fuzzy:true, compound:true, domains:["phonepe.com"]},
    github: {fuzzy:true, compound:true, domains:["github.com", "githubusercontent.com", "githubassets.com", "github.dev", "githubstatus.com", "githubapp.com", "github.blog"]}
  };
  // Real words (and other brands) one letter away from a brand name, or that start/end with one.
  // Built from the en_US Hunspell dictionary; keeps finance.yahoo.com from looking like "binance".
  const NOT_LOOKALIKES = new Set(["amazons", "amazonas", "amazonia", "amazonian", "amazonite", "papal", "paypay",
    "goggle", "goggles", "googles", "googly", "discoid", "discords", "discordance", "discordancy", "discordant", "finance", "phoneme"]);
  // Words that turn a brand mention into a sign-in / payment lure.
  const LURE_WORDS = new Set(["login", "logon", "signin", "sign", "auth", "account", "accounts", "verify", "verification",
    "secure", "security", "support", "help", "helpdesk", "service", "services", "update", "confirm", "billing", "payment",
    "pay", "wallet", "recover", "recovery", "unlock", "reset", "password", "kyc", "reward", "rewards", "gift", "giftcard",
    "bonus", "prize", "refund", "claim", "alert", "notice", "id", "online", "netbanking", "banking", "bank", "customer",
    "care", "center", "centre", "portal", "trade", "free", "nitro", "airdrop", "giveaway", "promo", "offer", "otp", "upi",
    "card", "redeem", "unblock", "blocked", "suspended", "limited", "restore"]);
  const ABUSED_ENDINGS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".click", ".icu", ".monster"];
  // Country endings often sold as generic names; brand.<these> is not assumed to be official.
  const GENERIC_CC = new Set(["io", "ai", "me", "tv", "cc", "ws", "to", "gg", "ly", "so", "sh", "co", "tk", "ml", "ga", "cf", "gq"]);
  const PRESSURE_WORDS = ["verify", "confirm", "suspended", "urgent", "unlock", "restore", "claim", "billing", "password",
    "secure-login", "account-update", "kyc", "refund", "reward", "otp", "blocked", "expire"];
  // Free hosting where anyone can publish under a subdomain (from the Public Suffix List's private section).
  const SHARED_SUFFIXES = ["github.io", "gitlab.io", "js.org", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "herokuapp.com", "appspot.com", "blogspot.com", "wixsite.com", "weebly.com", "wordpress.com",
    "glitch.me", "replit.app", "replit.dev", "repl.co", "onrender.com", "azurewebsites.net", "azurestaticapps.net",
    "web.core.windows.net", "blob.core.windows.net", "cloudfront.net", "amazonaws.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "trycloudflare.com", "surge.sh", "r2.dev", "webflow.io", "framer.app", "framer.website", "notion.site", "godaddysites.com",
    "square.site", "carrd.co", "myshopify.com", "sharepoint.com", "000webhostapp.com", "fly.dev", "railway.app", "deno.dev",
    "translate.goog", "my.canva.site", "mystrikingly.com", "jimdosite.com", "site123.me", "csb.app", "pythonanywhere.com",
    "atlassian.net", "zendesk.com", "freshdesk.com"];
  // Two-label public suffixes. Under any 2-letter country ending, these second levels are suffixes too (co.uk, com.au, gov.in…).
  const SECOND_LEVEL = new Set(["com", "net", "org", "gov", "edu", "ac", "co", "or", "ne", "go", "gob", "govt", "mil", "nic",
    "ltd", "plc", "sch", "nom", "gen", "firm", "ind", "res", "bank", "fin", "gv", "lg"]);
  const MULTI_SUFFIXES = new Set(["me.uk", "nhs.uk", "police.uk", "gr.jp", "ed.jp", "ad.jp", "web.id", "my.id", "biz.id", "in.th", "or.id"]);
  const URL_CHECKS = ["transport", "domain", "identity", "structure", "wording"];

  const brandEntries = Object.entries(BRANDS).map(([name, b]) => ({name, ...b, aliases:b.aliases || [], names:[name, ...(b.aliases || [])]}));
  const knownDomains = brandEntries.flatMap(b => b.domains);
  const PATH_DOMAIN_RE = new RegExp("/(?:" + knownDomains.filter(d => d.length >= 6).map(d => d.replace(/[.-]/g, "\\$&")).join("|") + ")(?:$|[/?#:])");
  const isIPv4 = host => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  const isIP = host => isIPv4(host) || host.startsWith("[");
  function isLoopback(host) {
    host = String(host || "").toLowerCase();
    return host === "localhost" || host.endsWith(".localhost") || /^127(?:\.\d{1,3}){3}$/.test(host) || host === "[::1]";
  }
  function onDomain(host, domain) { return host === domain || host.endsWith("." + domain); }

  // Split a hostname into subdomain / registrable label / public suffix.
  function splitHost(rawHost) {
    const host = String(rawHost || "").toLowerCase().replace(/\.$/, "");
    if (!host || isIP(host)) return {host, sub:"", label:host, suffix:"", reg:host, shared:false};
    const labels = host.split(".");
    let suffixLen = 1, shared = false;
    for (const s of SHARED_SUFFIXES) {
      const n = s.split(".").length;
      if (labels.length > n && host.endsWith("." + s) && n >= suffixLen) {suffixLen = n; shared = true;}
    }
    if (!shared && labels.length >= 3) {
      const last2 = labels.slice(-2).join(".");
      if (MULTI_SUFFIXES.has(last2) || (labels[labels.length - 1].length === 2 && SECOND_LEVEL.has(labels[labels.length - 2]))) suffixLen = 2;
    }
    if (labels.length <= suffixLen) return {host, sub:"", label:labels[0], suffix:labels.slice(1).join("."), reg:host, shared:false};
    return {
      host, shared,
      suffix: labels.slice(-suffixLen).join("."),
      label: labels[labels.length - suffixLen - 1],
      reg: labels.slice(-suffixLen - 1).join("."),
      sub: labels.slice(0, -suffixLen - 1).join(".")
    };
  }
  const registrableDomain = host => splitHost(host).reg;
  const sameSite = (a, b) => {
    const x = splitHost(a), y = splitHost(b);
    return Boolean(x.reg) && x.reg === y.reg;
  };

  // RFC 3492 Punycode decoder for xn-- labels.
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const adapt = (delta, numPoints, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) {delta = Math.floor(delta / (base - tMin)); k += base;}
      return k + Math.floor((base - tMin + 1) * delta / (delta + skew));
    };
    const out = [];
    let n = 128, i = 0, bias = 72;
    const basic = Math.max(0, input.lastIndexOf("-"));
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) return null;
      out.push(input.charCodeAt(j));
    }
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (index >= input.length) return null;
        const c = input.charCodeAt(index++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      if (n > 0x10ffff) return null;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  // Characters from other scripts that look like Latin letters.
  const CONFUSABLES = {"а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "у":"y", "х":"x", "ѕ":"s", "і":"i", "ј":"j", "ԁ":"d",
    "ԛ":"q", "ԝ":"w", "һ":"h", "ӏ":"l", "к":"k", "ɡ":"g", "ο":"o", "α":"a", "ρ":"p", "ν":"v", "ι":"i", "κ":"k", "χ":"x",
    "υ":"u", "ϲ":"c", "ı":"i", "ɑ":"a", "ⅼ":"l"};
  function idnSkeleton(host) {
    if (!host.includes("xn--")) return null;
    const decoded = host.split(".").map(label => label.startsWith("xn--") ? (punyDecode(label.slice(4)) ?? label) : label).join(".");
    return [...decoded].map(ch => CONFUSABLES[ch] ?? ch).join("");
  }
  function levenshtein(a, b) {
    let prev = Array.from({length:b.length + 1}, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }
  // Digit/letter swaps used in look-alike names: paypa1, g00gle, arnazon, 1cici.
  function homoglyphForms(token) {
    const base = token.replace(/0/g, "o").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t")
      .replace(/rn/g, "m").replace(/vv/g, "w");
    return [...new Set([base.replace(/1/g, "l"), base.replace(/1/g, "i")])];
  }
  function isOfficialFor(host, parts, b) {
    if (b.domains.some(d => onDomain(host, d))) return true;
    const tld = host.slice(host.lastIndexOf(".") + 1);
    if (b.names.includes(tld)) return true; // .google, .sbi and other brand-owned endings
    if (b.ccTLDs && !parts.shared && parts.label === b.name && !parts.sub.includes(b.name)) {
      const cc = parts.suffix.split(".").pop();
      return cc.length === 2 && !GENERIC_CC.has(cc) && !ABUSED_ENDINGS.some(e => host.endsWith(e));
    }
    return false;
  }
  function officialHost(host) {
    const parts = splitHost(host);
    return brandEntries.some(b => isOfficialFor(host, parts, b));
  }

  // Strongest single brand-identity clue for a hostname (or null).
  function identitySignal(host, parts) {
    const userPart = parts.sub ? parts.sub + "." + parts.label : parts.label;
    const tokens = userPart.split(/[._-]+/).filter(Boolean);
    const hasLure = tokens.some(t => LURE_WORDS.has(t));
    const subDotted = "." + parts.sub + ".";
    const skeleton = idnSkeleton(host);
    const skeletonTokens = skeleton ? skeleton.split(/[._-]+/).filter(Boolean) : [];
    let best = null;
    const offer = (sig) => {if (!best || sig.pts > best.pts) best = sig;};
    for (const b of brandEntries) {
      if (isOfficialFor(host, parts, b)) continue;
      const display = b.name;
      // 1. Official domain placed in the subdomain: paypal.com.evil.net, login.microsoftonline.com.x.ru
      if (parts.sub && b.domains.some(d => subDotted.includes("." + d + "."))) {
        offer({id:"embedded", title:"Official domain used as a subdomain", severity:"High", pts:62,
          desc:`${host} starts with a ${display} address, but the site is actually ${parts.reg}.`});
        continue;
      }
      // 2. IDN homograph: Cyrillic/Greek letters that render like the brand.
      if (skeleton && (skeletonTokens.some(t => b.names.includes(t) || (b.fuzzy && t.length >= 6 && Math.abs(t.length - b.name.length) <= 1 && levenshtein(t, b.name) === 1)) ||
          b.domains.some(d => onDomain(skeleton, d)))) {
        offer({id:"homoglyph", title:"Look-alike characters in the address", severity:"High", pts:62,
          desc:`${host} decodes to “${skeleton}”, which imitates ${display} using characters from another alphabet.`});
        continue;
      }
      // 3. Brand word in the address.
      const nameHit = tokens.find(t => b.names.includes(t));
      if (nameHit) {
        if (parts.label === nameHit && !parts.sub.split(/[._-]+/).some(t => LURE_WORDS.has(t))) {
          if (ABUSED_ENDINGS.some(e => host.endsWith(e))) {
            offer({id:"brand", title:"Possible brand impersonation", severity:"High", pts:62,
              desc:`${host} uses the ${display} name on a domain ending often used in abuse campaigns.`});
          } else {
            offer({id:"brand-unlisted", title:"Brand name on an unlisted domain", severity:"Low", pts:8,
              desc:`${parts.reg} carries the ${display} name but is not on PhishGuard's list of official ${display} domains. It may be a country or partner site; check before signing in.`});
          }
        } else if (b.common && !hasLure) {
          offer({id:"brand-word", title:"Brand name used in the address", severity:"Medium", pts:30,
            desc:`“${nameHit}” appears in ${host}, which is not an official ${display} domain. It may just be an ordinary word.`});
        } else {
          offer({id:"brand", title:"Possible brand impersonation", severity:"High", pts:62,
            desc:`The destination ${host} uses the ${display} name, but is not on the locally recognized official-domain list. Verify it independently.`});
        }
        continue;
      }
      // 4. Look-alike spelling: paypa1, arnazon, binanse, steamcommunuty.
      for (const t of tokens) {
        if (NOT_LOOKALIKES.has(t) || t.length < 3) continue;
        const forms = homoglyphForms(t);
        const swapped = forms.some(f => f !== t && b.names.includes(f));
        const typo = !swapped && forms.some(f => b.names.some(nm =>
          ((nm === b.name && b.fuzzy && nm.length >= 6) || (nm !== b.name && nm.length >= 8)) &&
          Math.abs(f.length - nm.length) <= 1 && f !== nm && levenshtein(f, nm) === 1));
        if (swapped || typo) {
          offer({id:"lookalike", title:"Possible brand lookalike", severity:"High", pts:58,
            desc:`“${t}” in ${host} closely resembles ${display}, but this is not an official ${display} domain. Verify it independently.`});
          break;
        }
      }
      // 5. Brand glued to other words: paypalsecure, netflixbilling.
      if (b.compound) {
        for (const t of tokens) {
          if (NOT_LOOKALIKES.has(t) || t.length < b.name.length + 2) continue;
          const rest = t.startsWith(b.name) ? t.slice(b.name.length) : t.endsWith(b.name) ? t.slice(0, -b.name.length) : null;
          if (rest === null) continue;
          const lure = LURE_WORDS.has(rest);
          offer({id:"brand-compound", title:lure ? "Brand name combined with account wording" : "Brand name inside a longer word",
            severity:lure ? "High" : "Medium", pts:lure ? 60 : 30,
            desc:`“${t}” in ${host} contains ${display}, but this is not an official ${display} domain.`});
          break;
        }
      }
    }
    return best;
  }

  function urlScore(rawUrl) {
    try {
      if (typeof rawUrl !== "string" || rawUrl.trim().length < 3 || rawUrl.length > 8192) throw new Error("Enter a valid website URL.");
      const text = rawUrl.trim();
      if (/\s|[\u0000-\u001f]/.test(text)) throw new Error("Remove spaces and control characters from the URL.");
      const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : "https://" + text);
      if (!["http:", "https:"].includes(url.protocol) || !url.hostname) throw new Error("Only HTTP and HTTPS website URLs can be scanned.");
      const host = url.hostname.toLowerCase().replace(/\.$/, "");
      const parts = splitHost(host);
      const loopback = isLoopback(host);
      const official = officialHost(host);
      const signals = [];
      const add = (id, title, desc, severity, pts) => signals.push({id, title, desc, severity, pts, source:"url"});
      if (url.protocol === "http:" && !loopback) add("https", "Unencrypted website", "The URL uses HTTP. Avoid providing sensitive details on this connection.", "Medium", 18);
      if (isIP(host) && !loopback) add("ip", "IP-address destination", "The address exposes an IP rather than a conventional domain name.", "Medium", 16);
      if (url.port && !["80", "443"].includes(url.port) && !loopback) add("port", "Unusual network port", "The URL uses a nonstandard port; this alone is not malicious.", "Low", 6);
      if (ABUSED_ENDINGS.some(t => host.endsWith(t))) add("tld", "Frequently abused domain ending", "This domain ending occurs in some abuse campaigns, but is not proof of phishing.", "Low", 9);
      if (host.includes("xn--")) add("idn", "Encoded internationalized hostname", "The hostname contains a Punycode label. Check for visually misleading characters.", "Medium", 14);
      if (!isIP(host)) {
        const identity = identitySignal(host, parts);
        if (identity) signals.push({...identity, source:"url"});
      }
      if (host.split(".").length > 5) add("sub", "Unusually deep subdomains", "Many subdomains may obscure which domain controls the site.", "Low", 7);
      if ((host.split(".")[0].replace(/^xn--/, "").match(/-/g) || []).length >= 3) add("hyphen", "Many hyphens in hostname", "A chain of hostname separators can make the address confusing.", "Low", 7);
      if (url.href.length > 150) add("len", "Long URL", "Long addresses can conceal their destination.", "Low", 5);
      if (url.username || url.password) add("userinfo", "Deceptive @-style URL", "The URL places text before @, which can conceal the true destination.", "High", 58);
      const path = url.pathname.toLowerCase();
      if (!official && PATH_DOMAIN_RE.test(path)) {
        add("brandpath", "Official-looking domain in URL path", "A trusted-looking domain appears in the path, not the actual hostname.", "Medium", 24);
      }
      const words = (host + path).toLowerCase();
      const found = PRESSURE_WORDS.filter(w => words.includes(w));
      if (!official) {
        const userWords = PRESSURE_WORDS.filter(w => parts.label.includes(w) || parts.sub.includes(w));
        if (parts.shared && userWords.length) {
          add("word", "Account-pressure wording on a free hosting address", `Free hosting subdomain uses “${userWords.slice(0, 3).join(", ")}”. Anyone can publish on ${parts.suffix}.`, "Medium", 26);
        } else if (found.length >= 2) {
          add("word", "Multiple account-pressure phrases", `The URL combines ${found.slice(0, 3).join(", ")}; verify who operates it.`, "Low", 10);
        }
      }
      return {ok:true, domain:host, url:url.href, score:Math.min(100, signals.reduce((n, s) => n + s.pts, 0)),
        signals:signals.sort((a, b) => b.pts - a.pts), checked:URL_CHECKS};
    } catch (e) {return {ok:false, error:e.message || "Invalid URL", checked:[], signals:[]};}
  }
  function riskBand(score) {return score >= HIGH_RISK ? "high" : score >= REVIEW_RISK ? "review" : "low";}

  return Object.freeze({HIGH_RISK, REVIEW_RISK, URL_CHECKS, BRANDS, urlScore, riskBand, splitHost, registrableDomain,
    sameSite, isLoopback, officialHost, punyDecode, idnSkeleton});
})();
