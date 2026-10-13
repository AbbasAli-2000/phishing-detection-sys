"""
Response Processing Module - URL feature extraction and rule-based scoring.

This module analyses a URL without contacting the network.
It extracts URL features and calculates a phishing risk score
between 0 and 100.
"""

import re
import ipaddress
from urllib.parse import urlparse


# Known URL-shortening services.
# These services hide the original destination of a shortened URL.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "bl.ink", "tiny.cc",
}


# Domain extensions that this detector treats as potentially suspicious.
# Having one of these extensions does not automatically mean a website is malicious.
SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "top", "xin", "tk", "ml", "ga", "cf", "buzz", "click",
    "rest", "monster", "quest", "cam", "loan", "mom",
}


# Brands and services that phishing websites may attempt to impersonate.
# Used to detect brand names appearing in suspicious URL locations.
TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "office365", "outlook", "netflix",
    "amazon", "facebook", "instagram", "whatsapp", "google", "gmail",
    "bank", "hbl", "meezan", "easypaisa", "jazzcash", "binance", "coinbase",
    "dhl", "fedex", "steam", "roblox", "icloud", "linkedin",
]


# Words commonly found in phishing URLs.
# These can indicate login, verification, account recovery or payment activity.
SENSITIVE_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "webscr", "recover", "unlock",
    "billing", "invoice", "wallet", "suspended", "limited",
]


# Normalize the submitted URL by trimming spaces and adding HTTPS
# when the user enters a domain without a scheme.
def normalise(url: str) -> str:
    url = (url or "").strip()

    # Return an empty string if no URL was provided.
    if not url:
        return ""

    # Add a scheme only when one is not already present.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


# Validate the URL format before performing analysis.
# Accept HTTP/HTTPS URLs with either a valid IP address or a domain-like hostname.
def is_valid(url: str) -> bool:
    parsed = urlparse(url)

    # Only HTTP and HTTPS schemes are accepted.
    if parsed.scheme not in ("http", "https"):
        return False

    # Extract the hostname and reject missing hosts or spaces.
    host = parsed.hostname or ""
    if not host or " " in host:
        return False

    # Accept a valid IPv4 or IPv6 address.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Check whether the hostname resembles a domain name.
    return bool(
        re.match(
            r"^(?=.{1,253}$)([a-z0-9_-]+\.)+[a-z]{2,}$",
            host,
            re.I
        )
    )


# Determine whether the hostname is an IPv4 or IPv6 address.
# Returns True for an IP address and False for a domain name.
def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Extract URL features that will be used by the scoring engine.
# This function analyses the URL structure without requesting the website.
def extract_features(url: str) -> dict:
    parsed = urlparse(url)

    # Extract the hostname, path and query string.
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Split the hostname into labels to inspect its subdomains and extension.
    labels = host.split(".") if host else []
    tld = labels[-1] if len(labels) > 1 else ""

    # Approximate the registered domain using the last two hostname labels.
    registered = ".".join(labels[-2:]) if len(labels) >= 2 else host

    return {
        # Total length of the URL and its hostname.
        "url_length": len(url),
        "host_length": len(host),

        # Check whether HTTPS is being used.
        "uses_https": parsed.scheme == "https",

        # Identify whether the hostname is an IP address.
        "host_is_ip": _host_is_ip(host),

        # Detect an @ symbol, which can make URL destinations confusing.
        "has_at_symbol": "@" in url,

        # Check whether an explicit port is present.
        "has_port": parsed.port is not None,

        # Count subdomains, excluding the presumed registered domain and TLD.
        "subdomain_count": (
            0 if _host_is_ip(host)
            else max(len(labels) - 2, 0)
        ),

        # Count hyphens and numeric characters in the hostname.
        "hyphen_count": host.count("-"),
        "digit_count": sum(c.isdigit() for c in host),

        # Check whether the presumed registered domain is a known shortener.
        "is_shortener": registered in SHORTENERS,

        # Check whether the top-level domain is in the suspicious TLD list.
        "suspicious_tld": tld in SUSPICIOUS_TLDS,

        # Detect punycode hostnames, which can sometimes disguise lookalike domains.
        "punycode": host.startswith("xn--") or ".xn--" in host,

        # Detect double slashes inside the URL path.
        "double_slash_in_path": "//" in path,

        # Find brand names appearing in suspicious hostname locations or the path.
        "brand_in_subdomain_or_path": [
            b for b in TARGET_BRANDS
            if (b in host and not registered.startswith(b + "."))
            or b in path.lower()
        ],

        # Find login, verification and other sensitive keywords in the path/query.
        "sensitive_words": [
            w for w in SENSITIVE_WORDS
            if w in (path + query).lower()
        ],

        # Count query-string parameters.
        "query_params": len([p for p in query.split("&") if p]),

        # Return hostname details for the API response and scoring.
        "host": host,
        "registered_domain": registered,
        "tld": tld,
    }


# Define fixed risk rules.
# Each tuple contains: feature name, risk points and explanation.
RULES = [
    ("host_is_ip", 25, "Uses a raw IP address instead of a domain name"),
    ("has_at_symbol", 20, "URL contains an '@' symbol, which can hide the real destination"),
    ("punycode", 20, "Punycode domain (xn--) — can visually impersonate a known brand"),
    ("is_shortener", 16, "Uses a URL shortener, so the real destination is hidden"),
    ("suspicious_tld", 12, "Domain ending has a high abuse rate"),
    ("has_port", 10, "URL specifies a non-standard port"),
    ("double_slash_in_path", 8, "Path contains a '//' redirect pattern"),
]


# Calculate the URL's risk score using extracted features.
# Returns the score, warning reasons and positive signals.
def score(features: dict) -> tuple[int, list[str], list[str]]:
    points = 0
    reasons: list[str] = []
    positives: list[str] = []

    # Apply the fixed risk points for every detected rule.
    for key, weight, text in RULES:
        if features.get(key):
            points += weight
            reasons.append(text)

    # Penalize URLs that do not use HTTPS.
    # HTTPS is a positive signal, but it does not guarantee that a site is safe.
    if not features["uses_https"]:
        points += 15
        reasons.append("Connection is not using HTTPS")
    else:
        positives.append("Connection uses HTTPS")

    # Penalize unusually long URLs.
    if features["url_length"] > 90:
        points += 10
        reasons.append(
            f"URL is unusually long ({features['url_length']} characters)"
        )
    elif features["url_length"] > 60:
        points += 5
        reasons.append("URL is longer than average")

    # Penalize URLs containing multiple subdomains.
    if features["subdomain_count"] >= 3:
        points += 12
        reasons.append(
            f"{features['subdomain_count']} subdomains — suspicious nesting"
        )
    elif features["subdomain_count"] == 2:
        points += 5
        reasons.append("Uses two subdomains")

    # Penalize domains containing several hyphens.
    if features["hyphen_count"] >= 3:
        points += 10
        reasons.append(
            "Domain contains several hyphens (a common typosquatting pattern)"
        )
    elif features["hyphen_count"] > 0:
        points += 3

    # Penalize hostnames containing many digits.
    if features["digit_count"] >= 4:
        points += 8
        reasons.append("Domain name contains a lot of digits")

    # Penalize brand names found in suspicious hostname locations or URL paths.
    brands = features["brand_in_subdomain_or_path"]
    if brands:
        points += 18
        reasons.append(
            f"Brand name '{brands[0]}' appears only in the subdomain/path, "
            "not the real domain"
        )

    # Add risk points for login and account-related keywords.
    words = features["sensitive_words"]
    if words:
        points += min(6 * len(words), 15)
        reasons.append(
            "Contains login/verification keywords: " + ", ".join(words[:4])
        )

    # Penalize URLs containing an unusually high number of query parameters.
    if features["query_params"] > 5:
        points += 5
        reasons.append("Query string has an unusually high number of parameters")

    # Add positive signals if no warning reasons were generated.
    if not reasons:
        positives.append("No phishing patterns found in the URL structure")

    # A simple domain structure is treated as a positive signal.
    if features["subdomain_count"] <= 1 and not features["host_is_ip"]:
        positives.append("Domain structure is simple and normal")

    # Cap the final risk score at 100.
    return min(points, 100), reasons, positives


# Convert the numeric risk score into a human-readable verdict.
# Score 0-27: safe; 28-54: suspicious; 55-100: phishing.
def verdict_from_score(points: int) -> str:
    if points >= 55:
        return "phishing"
    if points >= 28:
        return "suspicious"
    return "safe"


# Main analysis function called by the Flask API.
# Extract features, calculate the risk score and return all analysis results.
def analyse(url: str) -> dict:
    features = extract_features(url)
    points, reasons, positives = score(features)

    return {
        "features": features,
        "score": points,
        "verdict": verdict_from_score(points),
        "reasons": reasons,
        "positives": positives,
    }
