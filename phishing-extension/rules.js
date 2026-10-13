/*
 * Standalone rule-based phishing detector.
 * Mirrors the scoring logic in the Flask app's detector.py so the
 * extension can work without the backend running.
 */

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "bl.ink", "tiny.cc",
]);

const SUSPICIOUS_TLDS = new Set([
  "zip", "review", "country", "kim", "cricket", "science", "work", "party",
  "gq", "link", "top", "xin", "tk", "ml", "ga", "cf", "buzz", "click",
  "rest", "monster", "quest", "cam", "loan", "mom",
]);

const TARGET_BRANDS = [
  "paypal", "apple", "microsoft", "office365", "outlook", "netflix",
  "amazon", "facebook", "instagram", "whatsapp", "google", "gmail",
  "bank", "hbl", "meezan", "easypaisa", "jazzcash", "binance", "coinbase",
  "dhl", "fedex", "steam", "roblox", "icloud", "linkedin",
];

const SENSITIVE_WORDS = [
  "login", "signin", "verify", "verification", "secure", "account",
  "update", "confirm", "password", "webscr", "recover", "unlock",
  "billing", "invoice", "wallet", "suspended", "limited",
];

function isIpHost(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+$/i.test(host) && host.includes(":");
}

function extractFeatures(rawUrl) {
  const url = new URL(rawUrl);
  const host = (url.hostname || "").toLowerCase();
  const path = url.pathname || "";
  const query = url.search ? url.search.slice(1) : "";
  const labels = host ? host.split(".") : [];
  const tld = labels.length > 1 ? labels[labels.length - 1] : "";
  const registered = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  const lowerPathQuery = (path + query).toLowerCase();

  return {
    urlLength: rawUrl.length,
    hostLength: host.length,
    usesHttps: url.protocol === "https:",
    hostIsIp: isIpHost(host),
    hasAtSymbol: rawUrl.includes("@"),
    hasPort: !!url.port,
    subdomainCount: Math.max(labels.length - 2, 0),
    hyphenCount: (host.match(/-/g) || []).length,
    digitCount: (host.match(/\d/g) || []).length,
    isShortener: SHORTENERS.has(registered),
    suspiciousTld: SUSPICIOUS_TLDS.has(tld),
    punycode: host.startsWith("xn--") || host.includes(".xn--"),
    doubleSlashInPath: path.includes("//"),
    brandInSubdomainOrPath: TARGET_BRANDS.filter(
      (b) => (host.includes(b) && !registered.startsWith(b + ".")) || path.toLowerCase().includes(b)
    ),
    sensitiveWords: SENSITIVE_WORDS.filter((w) => lowerPathQuery.includes(w)),
    queryParams: query.split("&").filter(Boolean).length,
    host,
    registeredDomain: registered,
    tld,
  };
}

const RULES = [
  ["hostIsIp", 25, "Uses a raw IP address instead of a domain name"],
  ["hasAtSymbol", 20, "URL contains an '@' symbol, which can hide the real destination"],
  ["punycode", 20, "Punycode domain (xn--) — can visually impersonate a known brand"],
  ["isShortener", 16, "Uses a URL shortener, so the real destination is hidden"],
  ["suspiciousTld", 12, "Domain ending has a high abuse rate"],
  ["hasPort", 10, "URL specifies a non-standard port"],
  ["doubleSlashInPath", 8, "Path contains a '//' redirect pattern"],
];

function scoreFeatures(f) {
  let points = 0;
  const reasons = [];
  const positives = [];

  for (const [key, weight, text] of RULES) {
    if (f[key]) {
      points += weight;
      reasons.push(text);
    }
  }

  if (!f.usesHttps) {
    points += 15;
    reasons.push("Connection is not using HTTPS");
  } else {
    positives.push("Connection uses HTTPS");
  }

  if (f.urlLength > 90) {
    points += 10;
    reasons.push(`URL is unusually long (${f.urlLength} characters)`);
  } else if (f.urlLength > 60) {
    points += 5;
    reasons.push("URL is longer than average");
  }

  if (f.subdomainCount >= 3) {
    points += 12;
    reasons.push(`${f.subdomainCount} subdomains — suspicious nesting`);
  } else if (f.subdomainCount === 2) {
    points += 5;
    reasons.push("Uses two subdomains");
  }

  if (f.hyphenCount >= 3) {
    points += 10;
    reasons.push("Domain contains several hyphens (a common typosquatting pattern)");
  } else if (f.hyphenCount > 0) {
    points += 3;
  }

  if (f.digitCount >= 4) {
    points += 8;
    reasons.push("Domain name contains a lot of digits");
  }

  if (f.brandInSubdomainOrPath.length) {
    points += 18;
    reasons.push(
      `Brand name '${f.brandInSubdomainOrPath[0]}' appears only in the subdomain/path, not the real domain`
    );
  }

  if (f.sensitiveWords.length) {
    points += Math.min(6 * f.sensitiveWords.length, 15);
    reasons.push("Contains login/verification keywords: " + f.sensitiveWords.slice(0, 4).join(", "));
  }

  if (f.queryParams > 5) {
    points += 5;
    reasons.push("Query string has an unusually high number of parameters");
  }

  if (!reasons.length) {
    positives.push("No phishing patterns found in the URL structure");
  }
  if (f.subdomainCount <= 1 && !f.hostIsIp) {
    positives.push("Domain structure is simple and normal");
  }

  return { score: Math.min(points, 100), reasons, positives };
}

function verdictFromScore(points) {
  if (points >= 55) return "phishing";
  if (points >= 28) return "suspicious";
  return "safe";
}

function analyseUrl(rawUrl) {
  const features = extractFeatures(rawUrl);
  const { score, reasons, positives } = scoreFeatures(features);
  return { features, score, verdict: verdictFromScore(score), reasons, positives };
}
