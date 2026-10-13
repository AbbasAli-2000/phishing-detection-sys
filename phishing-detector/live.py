"""Live checks on a URL: DNS, SSL certificate, domain age (RDAP), redirects,
and (optionally) Google Safe Browsing.

A failed check is never treated as evidence of phishing unless the machine is
online: if there is no internet at all, live checks are skipped.
"""

import datetime as dt
import ipaddress
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 4
UA = {"User-Agent": "Mozilla/5.0 (PhishingDetector)"}


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _resolve(host):
    try:
        return {i[4][0] for i in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return set()


def _is_public(ips):
    return bool(ips) and all(ipaddress.ip_address(i.split("%")[0]).is_global for i in ips)


def _ssl(host, port=443):
    try:
        with socket.create_connection((host, port), TIMEOUT) as raw, \
                ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "why": e.verify_message}
    except OSError:
        return {"ok": False, "why": "could not open a secure connection"}
    issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "an unknown authority")
    end = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    return {"ok": True, "issuer": issuer, "days": (end - _now()).days}


def _age_days(domain):
    try:
        data = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, headers=UA).json()
        for e in data.get("events", []):
            if e.get("eventAction") == "registration":
                born = dt.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                return (_now() - born).days
    except (requests.RequestException, ValueError, KeyError, TypeError):
        pass
    return None


def _redirects(url):
    """Follow redirects by hand, refusing to fetch internal or unresolvable hosts."""
    hops, cur = 0, url
    for _ in range(5):
        parts = urlparse(cur)
        if parts.scheme not in ("http", "https") or not _is_public(_resolve(parts.hostname or "")):
            break
        try:
            r = requests.get(cur, headers=UA, timeout=TIMEOUT, allow_redirects=False, stream=True)
            r.close()
        except requests.RequestException:
            break
        loc = r.headers.get("Location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            cur, hops = urljoin(cur, loc), hops + 1
        else:
            break
    return hops, cur


def _safe_browsing(url):
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return False
    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                          json=body, timeout=TIMEOUT)
        return bool(r.json().get("matches"))
    except (requests.RequestException, ValueError):
        return False


def _registered(host):
    return ".".join(host.split(".")[-2:])


def check(url, f):
    """Return (extra risk points, warnings, good signs, live_available)."""
    if f["host_is_ip"]:
        return 0, [], [], True
    if not _resolve("example.com"):  # control lookup: are we online at all?
        return 0, [], [], False
    if not _resolve(f["host"]):
        return 40, ["This domain does not exist (no DNS record)"], [], True

    domain, https = f["registered_domain"], url.startswith("https")
    with ThreadPoolExecutor(4) as ex:
        ssl_job = ex.submit(_ssl, f["host"]) if https else None
        age_job = ex.submit(_age_days, domain)
        red_job = ex.submit(_redirects, url)
        sb_job = ex.submit(_safe_browsing, url)
        cert, age = (ssl_job.result() if ssl_job else None), age_job.result()
        (hops, final), flagged = red_job.result(), sb_job.result()

    pts, bad, good = 0, [], []
    if flagged:
        pts += 80
        bad.append("Flagged as unsafe by Google Safe Browsing")
    if cert:
        if cert["ok"]:
            good.append(f"Valid SSL certificate from {cert['issuer']}")
        else:
            pts += 30
            bad.append(f"SSL certificate problem: {cert['why']}")
    if age is not None:
        if age < 30:
            pts += 35
            bad.append(f"Domain was registered only {age} days ago")
        elif age < 180:
            pts += 15
            bad.append(f"Domain is only {age // 30} months old")
        elif age >= 730:
            good.append(f"Domain registered {age // 365} years ago")
    landed = _registered(urlparse(final).hostname or "")
    if hops and landed != domain:
        pts += 20
        bad.append(f"Redirects to a different site ({landed})")
    return pts, bad, good, True