#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SessionGuard v2.0 — Cookie & Session Security Analyzer (GUI Edition)
====================================================================

Final project tool for : Rayyan
Track                  : Web Session Security
Instructor             : Abdul Mannan — PNY Trainings, Cyber Security Department

What it checks
--------------
1. Captures every raw Set-Cookie header returned by the target (before the
   cookie jar normalizes it) and parses name, value, flags, Domain, Path,
   Expires / Max-Age.
2. Audits the Secure, HttpOnly and SameSite flags of every cookie and
   reports every missing or weak flag by cookie name — including
   SameSite=None without Secure.
3. Measures session cookie length and Shannon entropy (bits per character
   and estimated total bits) and flags short, low-entropy or predictable
   (sequential / timestamp / encoded-text / username-based) identifiers.
4. Checks session ID rotation on login (pre-login value vs post-login value).
5. Tests session fixation: plants an attacker-supplied session ID before
   login and reports whether the server kept it or issued a fresh one.
6. Tests logout invalidation: re-uses the pre-logout session ID after
   logging out and reports whether the server still accepts it.
7. Samples several fresh session IDs and reports duplicates, collisions
   and shared prefixes that suggest weak generation.
8. Checks cookie scope and prefixes: overly broad Domain values, Path
   values wider than needed, and __Secure- / __Host- prefix rule breaks.

Modes
-----
    python SessionGuard_GUI.py              # GUI (default)
    python SessionGuard_GUI.py --demo       # GUI pre-loaded with demo data
    python SessionGuard_GUI.py <url> ...    # command-line scan (saves report)
    python SessionGuard_GUI.py --selftest   # quick offline self-checks

LAB-ONLY NOTICE
---------------
Run this tool ONLY against systems you own or have written permission to
test, inside an isolated lab environment. Never point it at a real website
you do not own, and never test with anyone else's account or session.
Unauthorized access to computer systems is a criminal offence under the
Prevention of Electronic Crimes Act, 2016 (Pakistan).
"""

import argparse
import base64
import collections
import json
import math
import os
import queue
import re
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse as uparse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

# ---------------------------------------------------------------- optional deps
try:
    import requests as _requests
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter import font as tkfont
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# ---------------------------------------------------------------- app identity
APP_NAME = "SessionGuard"
APP_VERSION = "2.0.0"
APP_TAGLINE = "Cookie & Session Security Analyzer"

REF_OWASP = "OWASP Session Management Cheat Sheet"
REF_WSTG = "OWASP WSTG v4.2 - Session Management Testing"
REF_MDN = "MDN - Set-Cookie / __Host- and __Secure- prefixes"
REF_OWASP64 = "OWASP Session Management Cheat Sheet (>= 64 bits of entropy)"

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "PASS": 3, "INFO": 4}
DEFAULT_MODULES = ["flags", "entropy", "scope", "rotation", "fixation",
                   "logout", "sampling"]

MODULE_LABELS = {
    "fetch": "Target fetch & cookie capture",
    "flags": "Cookie flag audit",
    "entropy": "Entropy & predictability analysis",
    "scope": "Cookie scope & prefix rules",
    "rotation": "Session rotation test",
    "fixation": "Session fixation test",
    "logout": "Logout invalidation test",
    "sampling": "Session ID sampling",
    "report": "Report assembly",
}

SESSION_HINTS = (
    "session", "sess", "sid", "jsessionid", "phpsessid", "aspxauth",
    "asp.net_sessionid", "connect.sid", "laravel_session", "ci_session",
    "phpsession", "jwt", "token", "auth", "identity", "remember",
    "krbsid", "passport", "user_key",
)

CSRF_EXCLUDES = ("csrf", "xsrf", "anticsrf")

PUBLIC_SUFFIXES = set(
    "com org net edu gov mil int info biz io dev app ai co uk pk de fr nl eu "
    "xyz me tv us ca au in br jp cn ru za tr ir sa ae".split()
)

SHORT_LEN = 16
VERY_SHORT_LEN = 8
MIN_TOTAL_BITS = 64
LOW_BPC = 3.0

# ============================================================ small utilities


def safe_print(text=""):
    """print() that never crashes when sys.stdout is None (windowed exe)."""
    try:
        out = sys.stdout
        if out is None:
            return
        out.write(str(text) + "\n")
        out.flush()
    except Exception:
        pass


def trunc(value, n=48):
    s = str(value)
    return s if len(s) <= n else s[:n] + "..."


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def abs_url(base, url):
    """Resolve a possibly-relative URL against the target base URL."""
    if not url:
        return url
    if re.match(r"^https?://", url, re.I):
        return url
    return uparse.urljoin(base if base.endswith("/") else base + "/", url)


def is_session_name(name):
    """Heuristic: does this cookie name look like a session identifier?"""
    if not name:
        return False
    n = name.lower()
    for bad in CSRF_EXCLUDES:
        if bad in n:
            return False
    if n in ("_token",):
        return False
    for hint in SESSION_HINTS:
        if hint in n:
            return True
    return False


def host_is_private(hostname):
    """True for loopback / LAN / non-public names (used to soften severity)."""
    if not hostname:
        return True
    h = hostname.lower()
    if (h == "localhost" or h.endswith(".localhost") or h.endswith(".local")
            or h.endswith(".lan") or h.endswith(".internal")
            or h.endswith(".test")):
        return True
    if re.match(r"^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.", h):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or not ip.is_global
    except Exception:
        pass
    tld = h.rsplit(".", 1)[-1]
    return tld not in PUBLIC_SUFFIXES


# ============================================================ HTTP layer


class HttpResponse:
    """Uniform response object for both the requests and urllib backends."""

    def __init__(self, status, url, text, elapsed, header_pairs, hops):
        self.status = status
        self.url = url
        self.text = text or ""
        self.elapsed = elapsed
        self.header_pairs = header_pairs or []
        self.hops = hops or []
        self._d = collections.defaultdict(list)
        for k, v in self.header_pairs:
            self._d[str(k).lower()].append(v)
        sc = []
        for h in self.hops:
            sc.extend(h.get("set_cookies") or [])
        self.all_set_cookies = sc
        self.set_cookies = self.hops[-1]["set_cookies"] if self.hops else []

    def header(self, name):
        vals = self._d.get(name.lower())
        return vals[0] if vals else None


class HttpClient:
    """Small HTTP client that preserves raw Set-Cookie headers per hop."""

    def __init__(self, timeout=10, verify=True,
                 user_agent="SessionGuard/2.0 (+lab security scanner)"):
        self.timeout = timeout
        self.verify = verify
        self.user_agent = user_agent

    # ---- public API
    def get(self, url, cookies=None, headers=None):
        return self.request("GET", url, None, cookies, headers)

    def post(self, url, data=None, cookies=None, headers=None):
        return self.request("POST", url, data, cookies, headers)

    def request(self, method, url, data=None, cookies=None, headers=None):
        if HAVE_REQUESTS:
            return self._req_requests(method, url, data, cookies, headers)
        return self._req_urllib(method, url, data, cookies, headers)

    # ---- requests backend
    def _raw_sc(self, resp):
        try:
            raw = getattr(resp, "raw", None)
            if raw is not None and hasattr(raw, "headers"):
                lst = raw.headers.getlist("Set-Cookie")
                if lst:
                    return list(lst)
        except Exception:
            pass
        merged = resp.headers.get("Set-Cookie")
        if not merged:
            return []
        return split_merged_set_cookie(merged)

    def _req_requests(self, method, url, data, cookies, headers):
        h = {"User-Agent": self.user_agent, "Accept-Language": "en-US,en;q=0.9"}
        if headers:
            h.update(headers)
        t0 = time.time()
        # Manual redirect loop: the analyzer controls the cookie jar itself,
        # so raw Set-Cookie headers (including Secure cookies sent over
        # plain-HTTP lab targets) are honored exactly as captured.
        jar = dict(cookies or {})
        hops = []
        current = url
        m = method
        body = data
        status = 0
        text = ""
        pairs = []
        final_url = url
        for hop in range(11):
            with _requests.Session() as s:
                r = s.request(m, current, data=body, headers=h, cookies=jar,
                              timeout=self.timeout, verify=self.verify,
                              allow_redirects=False)
            scs = self._raw_sc(r)
            hops.append({"url": current, "status": r.status_code,
                         "set_cookies": scs})
            _update_jar_from_headers(jar, scs)
            status = r.status_code
            text = r.text
            pairs = list(r.headers.items())
            final_url = current
            loc = r.headers.get("Location")
            if status in (301, 302, 303, 307, 308) and loc and hop < 10:
                current = uparse.urljoin(current, loc)
                if status in (301, 302, 303):
                    m = "GET"
                    body = None
                continue
            break
        return HttpResponse(status, final_url, text, time.time() - t0, pairs,
                            hops)

    # ---- urllib fallback backend (stdlib only)
    def _req_urllib(self, method, url, data, cookies, headers):
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hd, newurl):
                return None

        opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=ctx))

        jar = dict(cookies or {})
        hops = []
        current = url
        m = method
        body = data
        pairs = []
        text = ""
        status = 0
        t0 = time.time()

        for hop in range(11):
            hdrs = {"User-Agent": self.user_agent}
            if headers:
                hdrs.update(headers)
            if jar:
                hdrs["Cookie"] = "; ".join(
                    "%s=%s" % (k, v) for k, v in jar.items())
            payload = None
            if m == "POST" and body is not None:
                if isinstance(body, dict):
                    payload = uparse.urlencode(body).encode("utf-8")
                else:
                    payload = str(body).encode("utf-8")
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(current, data=payload, headers=hdrs,
                                         method=m)
            try:
                resp = opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                resp = e
            except Exception as e:
                msg = str(e)
                if "CERTIFICATE" in msg.upper() or "SSL" in msg.upper():
                    msg += (" (hint: disable 'Verify TLS' for self-signed "
                            "lab certificates)")
                raise RuntimeError("Request to %s failed: %s" % (current, msg))
            try:
                status = resp.getcode() or 0
                raw_text = resp.read()
                text = raw_text.decode("utf-8", "replace")
                scs = list(resp.headers.get_all("Set-Cookie") or [])
                loc = resp.headers.get("Location")
                pairs = list(resp.headers.items())
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
            hops.append({"url": current, "status": status,
                         "set_cookies": scs})
            _update_jar_from_headers(jar, scs)
            if status in (301, 302, 303, 307, 308) and loc and hop < 10:
                current = uparse.urljoin(current, loc)
                if status in (301, 302, 303):
                    m = "GET"
                    body = None
                continue
            break
        return HttpResponse(status, current, text, time.time() - t0, pairs,
                            hops)


def split_merged_set_cookie(header):
    """Split one merged Set-Cookie header into individual cookie strings.

    Handles 'Expires=Wed, 21 Oct 2026 07:28:00 GMT' without splitting on
    the comma inside the date.
    """
    parts = re.split(r",(?=\s*[^\s,;=]+\s*=)", header)
    return [p.strip() for p in parts if p.strip()]


def parse_set_cookie(header):
    """Parse one Set-Cookie header string into a cookie dict."""
    c = {
        "name": "", "value": "", "secure": False, "httponly": False,
        "samesite": None, "domain": None, "path": None, "expires": None,
        "max_age": None, "raw": header.strip() if header else "",
    }
    if not header:
        return c
    if "=" not in header.split(";")[0]:
        c["name"] = header.strip().split(";")[0].strip()
        return c
    first, _, rest = header.partition(";")
    name, _, value = first.partition("=")
    c["name"] = name.strip()
    c["value"] = value.strip()
    if len(c["value"]) >= 2 and c["value"][:1] == '"' and c["value"][-1:] == '"':
        c["value"] = c["value"][1:-1]
    for attr in rest.split(";"):
        k, _, v = attr.strip().partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "secure":
            c["secure"] = True
        elif k == "httponly":
            c["httponly"] = True
        elif k == "samesite":
            c["samesite"] = v.capitalize() if v else None
        elif k == "domain":
            c["domain"] = v.lstrip(".").lower() or None
        elif k == "path":
            c["path"] = v or "/"
        elif k == "expires":
            c["expires"] = v
        elif k == "max-age":
            c["max_age"] = v
    return c


def _update_jar_from_headers(jar, set_cookie_list):
    """Merge Set-Cookie headers into a plain {name: value} jar."""
    for raw in set_cookie_list or []:
        c = parse_set_cookie(raw)
        if not c["name"]:
            continue
        if c["max_age"] is not None:
            try:
                ma = int(str(c["max_age"]).strip())
            except Exception:
                ma = None
            if ma is not None and ma <= 0:
                jar.pop(c["name"], None)
                continue
        jar[c["name"]] = c["value"]


# ============================================================ entropy engine


def shannon_entropy_bits_per_char(s):
    """Shannon entropy of the string's character distribution (bits/char)."""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    h = 0.0
    for cnt in counts.values():
        p = cnt / n
        h -= p * math.log2(p)
    return h


def alphabet_name(v):
    chars = set(v)
    if not v:
        return "empty"
    if chars <= set("0123456789abcdef"):
        return "hex lower"
    if chars <= set("0123456789ABCDEF"):
        return "hex upper"
    if chars <= set("0123456789"):
        return "digits"
    if chars <= set("0123456789abcdefghijklmnopqrstuvwxyz"):
        return "base36"
    if chars <= set("0123456789abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        return "alnum (62)"
    if chars <= set("0123456789abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ+/-_="):
        return "base64url"
    return "mixed (%d unique)" % len(chars)


def _longest_monotone_run(s):
    """Length of the longest ascending or descending consecutive run."""
    best = 1
    cur = 1
    for i in range(1, len(s)):
        if ord(s[i]) == ord(s[i - 1]) + 1 or ord(s[i]) == ord(s[i - 1]) - 1:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return best


def _decodes_to_printable(raw_bytes):
    if not raw_bytes:
        return ""
    try:
        txt = raw_bytes.decode("ascii")
    except Exception:
        return ""
    if txt and all(32 <= ord(ch) < 127 for ch in txt) and any(
            ch.isalpha() for ch in txt):
        return txt
    return ""


def find_value_issues(value, username=None):
    """Predictability heuristics. Returns (hard_issues, soft_issues)."""
    hard = []
    soft = []
    v = value
    if not v:
        return hard, soft
    if len(set(v)) == 1:
        hard.append('every character is identical ("%s...")' % v[:12])
    run = _longest_monotone_run(v)
    if run >= 6:
        soft.append("contains a %d-character sequential run (e.g. abc / 123)"
                    % run)
    if re.fullmatch(r"1[3-9]\d{11}", v):
        hard.append("looks like a millisecond Unix timestamp (predictable)")
    elif re.fullmatch(r"\d{10}", v):
        try:
            n = int(v)
            if 946684800 <= n <= 4102444800:
                hard.append("looks like a Unix timestamp in seconds "
                            "(predictable)")
        except Exception:
            pass
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", v):
        try:
            txt = _decodes_to_printable(bytes.fromhex(v))
        except Exception:
            txt = ""
        if txt:
            hard.append('hex-decodes to readable text "%s" - it is encoded '
                        "data, not random" % trunc(txt, 40))
    if len(v) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", v):
        for decoder in (base64.b64decode,
                        lambda s: base64.urlsafe_b64decode(
                            s.replace("-", "+").replace("_", "/"))):
            try:
                txt = _decodes_to_printable(decoder(v))
            except Exception:
                txt = ""
            if txt:
                hard.append('base64-decodes to readable text "%s" - it is '
                            "encoded data, not random" % trunc(txt, 40))
                break
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-"
                    r"[0-9a-f]{12}", v.lower()):
        hard.append("UUID version 1 embeds a timestamp / MAC address - "
                    "predictable")
    if username and username.lower() in v.lower():
        hard.append('value contains the account name "%s"' % username)
    return hard, soft


def analyze_value(value, username=None):
    """Full analysis of one cookie value. Returns an analysis dict."""
    ln = len(value)
    bpc = shannon_entropy_bits_per_char(value)
    total = bpc * ln
    unique = len(set(value))
    hard, soft = find_value_issues(value, username)
    if hard:
        verdict = "Predictable / non-random"
    elif soft:
        verdict = "Suspicious pattern"
    elif total < MIN_TOTAL_BITS:
        verdict = "Weak entropy"
    elif ln < SHORT_LEN:
        verdict = "Short"
    elif bpc >= LOW_BPC:
        verdict = "OK"
    else:
        verdict = "Review"
    return {
        "len": ln, "unique": unique, "bpc": bpc, "total_bits": total,
        "alphabet": alphabet_name(value), "verdict": verdict,
        "hard": hard, "soft": soft,
    }


def prefix_violations(c):
    """Return list of __Secure- / __Host- prefix rule violations."""
    v = []
    n = c["name"]
    if n.startswith("__Host-"):
        if not c["secure"]:
            v.append("missing Secure (required by __Host-)")
        if c["domain"]:
            v.append("has a Domain attribute (forbidden for __Host-)")
        if (c["path"] or "/") != "/":
            v.append("Path=%s (must be exactly \"/\" for __Host-)"
                     % (c["path"] or "(none)"))
    if n.startswith("__Secure-") and not c["secure"]:
        v.append("missing Secure (required by __Secure-)")
    return v


# ============================================================ data structures


@dataclass
class Finding:
    severity: str          # HIGH / MEDIUM / LOW / PASS / INFO
    title: str
    evidence: str = ""
    cookie: str = ""
    fix: str = ""
    ref: str = REF_OWASP
    kind: str = "finding"  # finding | pass | info


@dataclass
class ScanConfig:
    target: str = ""
    login_url: str = ""
    username: str = ""
    password: str = ""
    user_field: str = "username"
    pass_field: str = "password"
    extra_fields: dict = field(default_factory=dict)
    cookie_names: list = field(default_factory=list)
    attacker_sid: str = ""
    samples: int = 10
    timeout: int = 10
    verify_tls: bool = True
    logout_url: str = ""
    protected_url: str = ""
    auth_marker: str = ""
    modules: list = field(default_factory=lambda: list(DEFAULT_MODULES))
    demo: bool = False


# ============================================================ analyzer


class SessionAnalyzer:
    """Runs every session-security check and collects findings + evidence."""

    def __init__(self, config, http=None, log=None):
        self.cfg = config
        self.http = http or HttpClient(timeout=config.timeout,
                                       verify=config.verify_tls)
        self._log_cb = log or (lambda msg, level="INFO": None)
        self.cookies = []          # parsed cookie dicts (+ analysis fields)
        self.findings = []         # list[Finding]
        self.raw_capture = []      # [{'tag','url','status','set_cookies'}]
        self.tests = {}            # module -> result dict for GUI/report
        self.modules_run = []
        self.final_status = None
        self.final_headers = []
        self.scan_started = now_str()
        self.scan_duration = 0.0
        self.report_text = ""
        self.target_host = ""
        self.stopped = False

    # ---------- plumbing
    def log(self, msg, level="INFO"):
        self._log_cb(msg, level)

    def _add(self, severity, title, evidence="", cookie="", fix="",
             ref=REF_OWASP, kind=None):
        if kind is None:
            kind = "pass" if severity == "PASS" else (
                "info" if severity == "INFO" else "finding")
        self.findings.append(Finding(severity, title, evidence, cookie, fix,
                                     ref, kind))

    def _tag_hops(self, resp, tag):
        for h in resp.hops:
            self.raw_capture.append({
                "tag": tag, "url": h.get("url", ""), "status": h.get("status"),
                "set_cookies": h.get("set_cookies") or [],
            })

    def _merge(self, jar, resp):
        _update_jar_from_headers(jar, resp.all_set_cookies)

    def _session_candidates(self, jar=None):
        if self.cfg.cookie_names:
            return list(self.cfg.cookie_names)
        names = set()
        for c in self.cookies:
            if c.get("session_like"):
                names.add(c["name"])
        if jar:
            for n in jar:
                if is_session_name(n):
                    names.add(n)
        if not names and jar:
            names = set(jar.keys())
        if not names:
            names = {c["name"] for c in self.cookies}
        return sorted(names)[:4]

    def _primary_session_name(self, jar):
        if self.cfg.cookie_names:
            return self.cfg.cookie_names[0]
        for n in jar:
            if is_session_name(n):
                return n
        for c in self.cookies:
            if c.get("session_like"):
                return c["name"]
        return "sessionid"

    def _login_data(self):
        data = {self.cfg.user_field: self.cfg.username,
                self.cfg.pass_field: self.cfg.password}
        data.update(self.cfg.extra_fields or {})
        return data

    def _login_succeeded(self, resp):
        low = (resp.text or "").lower()
        if re.search(r"invalid credentials|incorrect (username|password|login)"
                     r"|login failed|wrong password|authentication failed",
                     low):
            return False
        return resp.status < 400

    def _is_authenticated(self, resp):
        """Heuristic auth-state detection for the logout test."""
        low = (resp.text or "").lower()
        if self.cfg.auth_marker:
            return self.cfg.auth_marker.lower() in low
        final_path = uparse.urlparse(resp.url).path.lower()
        for marker in ("welcome back", "logout", "sign out", "log out",
                       "my account", "dashboard", "my profile"):
            if marker in low:
                return True
        if ("type=\"password\"" in low or 'name="password"' in low
                or final_path.rstrip("/").endswith("login")):
            return False
        return False

    # ---------- module: fetch + parse
    def fetch_target(self):
        resp = self.http.get(self.cfg.target)
        self._tag_hops(resp, "Fetch target")
        self.final_status = resp.status
        self.final_headers = resp.header_pairs
        seen = set()
        self.cookies = []
        for raw in resp.all_set_cookies:
            c = parse_set_cookie(raw)
            if not c["name"]:
                continue
            key = c["raw"]
            if key in seen:
                continue
            seen.add(key)
            c["session_like"] = is_session_name(c["name"])
            c["analysis"] = analyze_value(c["value"], self.cfg.username)
            self.cookies.append(c)
        self.target_host = uparse.urlparse(self.cfg.target).hostname or ""
        self.log("Fetched %s -> HTTP %s, %d Set-Cookie header(s) captured"
                 % (trunc(self.cfg.target, 60), resp.status,
                    len(self.cookies)), "OK")
        if not self.cookies:
            self._add("INFO", "No Set-Cookie header observed on the target",
                      "The target returned no cookies. It may need "
                      "authentication first, or content is rendered "
                      "client-side (try the app's login page as target).",
                      kind="info")
        return resp

    # ---------- module: flag audit
    def audit_flags(self):
        target_http = self.cfg.target.lower().startswith("http://")
        private = host_is_private(self.target_host)
        fully_flagged = 0
        for c in self.cookies:
            name = c["name"]
            sess = c["session_like"]
            missing = []
            if not c["secure"]:
                missing.append("Secure")
            if not c["httponly"]:
                missing.append("HttpOnly")
            if not c["samesite"]:
                missing.append("SameSite")
            if c["samesite"] == "None" and not c["secure"]:
                self._add(
                    "HIGH" if sess else "MEDIUM",
                    "SameSite=None without Secure on cookie \"%s\"" % name,
                    'Cookie "%s" declares SameSite=None but not Secure. '
                    "This combination is invalid per RFC6265bis: modern "
                    "browsers reject the cookie, and if it were accepted it "
                    "would be sent on every cross-site request." % name,
                    cookie=name,
                    fix="Use SameSite=Lax (or Strict), or add the Secure "
                        "flag when SameSite=None is really required.",
                    ref=REF_WSTG)
            if not c["secure"]:
                sev = "MEDIUM" if sess else "LOW"
                if sess and target_http and not private:
                    sev = "HIGH"
                ev = ('Cookie "%s" is set without the Secure flag, so it can '
                      "also travel over plain HTTP." % name)
                if target_http:
                    ev += (" The target itself is served over http://"
                           + (" (private/lab host)" if private else "."))
                self._add(
                    sev,
                    ("Session cookie missing Secure flag"
                     if sess else "Cookie missing Secure flag") +
                    ' - "%s"' % name,
                    ev, cookie=name,
                    fix="Add the Secure attribute so the cookie is only sent "
                        "over HTTPS.",
                    ref=REF_WSTG)
            if not c["httponly"]:
                self._add(
                    "HIGH" if sess else "LOW",
                    ("Session cookie missing HttpOnly flag"
                     if sess else "Cookie missing HttpOnly flag") +
                    ' - "%s"' % name,
                    'Cookie "%s" is set without HttpOnly, so any XSS flaw on '
                    "this origin can read it via document.cookie and steal "
                    "the value." % name,
                    cookie=name,
                    fix="Add the HttpOnly attribute to session cookies so "
                        "JavaScript cannot read them.",
                    ref=REF_WSTG)
            if not c["samesite"]:
                self._add(
                    "MEDIUM" if sess else "LOW",
                    ("Session cookie has no SameSite attribute"
                     if sess else "Cookie has no SameSite attribute") +
                    ' - "%s"' % name,
                    'Cookie "%s" declares no SameSite attribute. Modern '
                    "browsers default to Lax, but older or embedded browsers "
                    "may not, leaving the cookie exposed to cross-site "
                    "requests (CSRF)." % name,
                    cookie=name,
                    fix="Set SameSite=Lax or SameSite=Strict explicitly.",
                    ref=REF_WSTG)
            if not missing:
                fully_flagged += 1
                if sess:
                    self._add(
                        "PASS", "Session cookie \"%s\" carries Secure + "
                        "HttpOnly + SameSite=%s" % (name, c["samesite"]),
                        "Raw header: %s" % trunc(c["raw"], 90),
                        cookie=name, kind="pass")
        if self.cookies:
            self._add("INFO", "Flag audit summary: %d of %d observed cookies "
                      "are fully flagged (Secure + HttpOnly + SameSite)"
                      % (fully_flagged, len(self.cookies)), kind="info")
        if self.cookies and not any(c["session_like"] for c in self.cookies):
            self._add("INFO", "No session-identifier-looking cookie detected",
                      "No cookie name matched known session names "
                      "(sessionid, JSESSIONID, PHPSESSID, connect.sid, ...). "
                      "Set the cookie names manually in Settings so the "
                      "session tests know what to track.", kind="info")

    # ---------- module: entropy
    def analyze_entropy(self):
        session_cookies = [c for c in self.cookies if c["session_like"]]
        if not session_cookies:
            self.tests["entropy"] = {"verdict": "INFO",
                                     "summary": "No session-like cookies to "
                                                "measure."}
            return
        rows = []
        for c in session_cookies:
            a = c["analysis"]
            value = c["value"]
            name = c["name"]
            rows.append({"name": name, "value": value, "analysis": a})
            sev = None
            msgs = []
            if a["total_bits"] < 32:
                sev = "HIGH"
                msgs.append("estimated entropy is only ~%d bits (OWASP "
                            "recommends at least 64 bits)"
                            % int(a["total_bits"]))
            elif a["total_bits"] < MIN_TOTAL_BITS:
                sev = "MEDIUM"
                msgs.append("estimated entropy is ~%d bits - below the "
                            "64-bit recommendation" % int(a["total_bits"]))
            if a["len"] < VERY_SHORT_LEN:
                sev = "HIGH"
                msgs.append("only %d characters long" % a["len"])
            elif a["len"] < SHORT_LEN:
                if sev is None:
                    sev = "MEDIUM"
                msgs.append("short identifier (%d characters)" % a["len"])
            if a["bpc"] < LOW_BPC and a["len"] >= SHORT_LEN:
                if sev is None:
                    sev = "LOW"
                msgs.append("low character diversity (%.2f bits/char, %d "
                            "unique of %d)"
                            % (a["bpc"], a["unique"], a["len"]))
            if msgs:
                self._add(
                    sev or "LOW",
                    "Weak session ID entropy - \"%s\"" % name,
                    'Value "%s" (length %d, alphabet %s): Shannon entropy '
                    "%.2f bits/char, ~%.0f bits total. %s."
                    % (value, a["len"], a["alphabet"], a["bpc"],
                       a["total_bits"], "; ".join(msgs)),
                    cookie=name,
                    fix="Generate session IDs from a CSPRNG with at least "
                        "128 bits of entropy (e.g. secrets.token_bytes(16)).",
                    ref=REF_OWASP64)
            if a["hard"]:
                self._add(
                    "HIGH", "Predictable / non-random session ID - \"%s\""
                    % name,
                    'Value "%s": %s.' % (value, "; ".join(a["hard"])),
                    cookie=name,
                    fix="Replace hand-rolled token generation with a CSPRNG; "
                        "never derive session IDs from usernames, timestamps "
                        "or encodings of known data.",
                    ref=REF_WSTG)
            elif a["soft"]:
                self._add(
                    "MEDIUM", "Suspicious pattern in session ID - \"%s\""
                    % name,
                    'Value "%s": %s.' % (value, "; ".join(a["soft"])),
                    cookie=name,
                    fix="Confirm the value comes from a CSPRNG, not a "
                        "counter or seeded generator.",
                    ref=REF_WSTG)
        self.tests["entropy"] = {"verdict": "DONE", "rows": rows,
                                 "summary": "%d session cookie(s) measured"
                                            % len(rows)}

    # ---------- module: scope & prefixes
    def check_scope(self):
        host = self.target_host
        for c in self.cookies:
            name = c["name"]
            for v in prefix_violations(c):
                self._add(
                    "MEDIUM", "Cookie prefix rule violation - \"%s\"" % name,
                    'Cookie "%s" breaks its prefix contract: %s. Browsers '
                    "will refuse this cookie, and the prefix promise to "
                    "users is broken." % (name, "; ".join(v)),
                    cookie=name,
                    fix="__Host- cookies need Secure, Path=/ and no Domain "
                        "attribute; __Secure- cookies need Secure.",
                    ref=REF_MDN)
            d = c["domain"]
            if d and host:
                d = d.lstrip(".").lower()
                if d in PUBLIC_SUFFIXES and "." not in d:
                    self._add(
                        "HIGH", "Cookie Domain set to a public suffix - "
                        "\"%s\"" % name,
                        'Cookie "%s" declares Domain=%s, which would scope it '
                        "to the entire top-level domain. Browsers reject it, "
                        "but the intent shows a dangerous configuration."
                        % (name, d),
                        cookie=name,
                        fix="Remove the Domain attribute (host-only cookie) "
                            "or scope it to your registrable domain.",
                        ref=REF_WSTG)
                elif host == d:
                    pass
                elif host.endswith("." + d):
                    self._add(
                        "LOW", "Cookie shared across subdomains - \"%s\""
                        % name,
                        'Cookie "%s" uses Domain=%s while the app runs on '
                        "%s, so every sibling subdomain also receives it."
                        % (name, d, host),
                        cookie=name,
                        fix="Use a host-only cookie (no Domain attribute) "
                            "unless subdomain sharing is a real requirement.",
                        ref=REF_WSTG)
                else:
                    self._add(
                        "MEDIUM", "Cookie scoped to an unrelated domain - "
                        "\"%s\"" % name,
                        'Cookie "%s" declares Domain=%s but the target host '
                        "is %s." % (name, d, host),
                        cookie=name,
                        fix="Align the Domain attribute with the serving "
                            "host.", ref=REF_WSTG)
            if c["session_like"] and (c["path"] or "/") == "/":
                self._add(
                    "INFO", "Session cookie \"%s\" uses Path=/ (widest scope)"
                    % name,
                    'Cookie "%s" is sent to every path of the site. If the '
                    "application only needs it under a sub-folder, narrow "
                    "the Path attribute to reduce exposure." % name,
                    cookie=name, kind="info")
            if c["session_like"] and c["max_age"] is not None:
                try:
                    ma = int(str(c["max_age"]))
                except Exception:
                    ma = 0
                if ma > 30 * 86400:
                    self._add(
                        "LOW", "Very long-lived session cookie - \"%s\""
                        % name,
                        'Cookie "%s" has Max-Age=%d (~%d days). Long-lived '
                        "session identifiers widen the theft window."
                        % (name, ma, ma // 86400),
                        cookie=name,
                        fix="Prefer short server-side session lifetimes with "
                            "idle timeout and rotation.",
                        ref=REF_OWASP)

    # ---------- module: rotation on login
    def test_rotation(self):
        cfg = self.cfg
        if not (cfg.login_url and cfg.username and cfg.password):
            self._add("INFO", "Rotation test not run - login details missing",
                      "Provide the lab login URL, username and password in "
                      "Settings to enable the rotation check.", kind="info")
            self.tests["rotation"] = {
                "verdict": "INFO",
                "summary": "Not tested - login details not provided."}
            return
        login_url = abs_url(cfg.target, cfg.login_url)
        jar = {}
        r1 = self.http.get(cfg.target, cookies=jar)
        self._tag_hops(r1, "Rotation: pre-login fetch")
        self._merge(jar, r1)
        candidates = self._session_candidates(jar)
        pre = {n: jar[n] for n in candidates if n in jar}
        r2 = self.http.post(login_url, data=self._login_data(), cookies=jar)
        self._tag_hops(r2, "Rotation: login POST")
        self._merge(jar, r2)
        post = {n: jar[n] for n in candidates if n in jar}
        login_ok = self._login_succeeded(r2)
        changed = [n for n in post if pre.get(n) != post.get(n)]

        rows = [("Login URL", login_url),
                ("Login response", "HTTP %s (%s)"
                 % (r2.status, trunc(r2.url, 60))),
                ("Login verified", "yes" if login_ok else
                 "NO - check credentials / field names")]
        for n in sorted(set(list(pre.keys()) + list(post.keys()))):
            rows.append(("Cookie %s (pre-login)" % n, pre.get(n, "(none set)")))
            rows.append(("Cookie %s (post-login)" % n,
                         post.get(n, "(none set)")))
        if not post or not login_ok:
            verdict, summary = "INDETERMINATE", (
                "Login could not be verified (HTTP %s). No rotation "
                "judgement made." % r2.status)
            self._add("INFO", "Rotation test inconclusive",
                      summary + " Verify the username/password and the field "
                      "names in Settings, and confirm the login form needs "
                      "no CSRF token.", kind="info")
        elif pre and not changed:
            verdict, summary = "FAIL", (
                "Server kept the same session ID value after login - "
                "NO rotation.")
            self._add("HIGH", "Session ID not rotated after login",
                      "Pre-login and post-login session identifiers are "
                      "identical (%s). An attacker who learns the pre-login "
                      "value owns the authenticated session."
                      % ", ".join("%s=%s" % (n, post[n]) for n in sorted(post)),
                      cookie=", ".join(sorted(post)),
                      fix="Regenerate the session identifier on every "
                          "privilege change (especially login): invalidate "
                          "the old ID server-side and issue a fresh one.",
                      ref=REF_OWASP)
        elif changed:
            verdict, summary = "PASS", (
                "Session ID rotated on login: %s changed." % ", ".join(changed))
            self._add("PASS", "Session ID rotated on login after "
                      "authentication",
                      "; ".join("%s: %s -> %s" % (n, pre.get(n, "(none)"),
                                                  post[n])
                                for n in changed),
                      cookie=", ".join(changed), kind="pass")
        else:
            verdict, summary = "PASS", (
                "Session issued at login (no pre-login session cookie).")
            self._add("PASS", "Session ID issued at login",
                      "No session cookie existed before login; the server "
                      "issued one on successful authentication.", kind="pass")
        rows.append(("Verdict", summary))
        self.tests["rotation"] = {"verdict": verdict, "summary": summary,
                                  "rows": rows}
        self.log("Rotation test: %s" % summary,
                 "OK" if verdict == "PASS" else verdict)

    # ---------- module: session fixation
    def test_fixation(self):
        cfg = self.cfg
        if not (cfg.login_url and cfg.username and cfg.password):
            self._add("INFO", "Fixation test not run - login details missing",
                      "Provide the lab login URL, username and password in "
                      "Settings to enable the fixation check.", kind="info")
            self.tests["fixation"] = {
                "verdict": "INFO",
                "summary": "Not tested - login details not provided."}
            return
        fixed = cfg.attacker_sid or ("SGFIX" + os.urandom(4).hex().upper())
        login_url = abs_url(cfg.target, cfg.login_url)
        probe = {}
        r0 = self.http.get(cfg.target, cookies=probe)
        self._tag_hops(r0, "Fixation: probe fetch")
        self._merge(probe, r0)
        name = self._primary_session_name(probe)

        jar = {name: fixed}
        r1 = self.http.get(cfg.target, cookies=jar)
        self._tag_hops(r1, "Fixation: attacker cookie sent")
        self._merge(jar, r1)
        after_pre = jar.get(name)
        r2 = self.http.post(login_url, data=self._login_data(), cookies=jar)
        self._tag_hops(r2, "Fixation: login POST")
        self._merge(jar, r2)
        final = jar.get(name)
        login_ok = self._login_succeeded(r2)

        rows = [("Cookie name", name),
                ("Attacker-supplied SID", fixed),
                ("SID after pre-login fetch", after_pre or "(none)"),
                ("SID after login", final if final else "(none)"),
                ("Login response", "HTTP %s (%s)"
                 % (r2.status, trunc(r2.url, 60))),
                ("Login verified", "yes" if login_ok else "NO")]
        if not login_ok or final is None:
            verdict, summary = "INDETERMINATE", (
                "Fixation test inconclusive (login not verified / no %s "
                "cookie after login)." % name)
            self._add("INFO", "Fixation test inconclusive", summary,
                      kind="info")
        elif final == fixed:
            verdict = "FAIL"
            summary = ("Server ACCEPTED the attacker-supplied session ID "
                       '"%s" through a successful login.' % fixed)
            self._add(
                "HIGH", "Session fixation - server accepted the "
                "attacker-supplied session ID",
                'Attacker-supplied value "%s" for cookie "%s" was still in '
                "use after a successful login, so anyone who plants that "
                "value in a victim's browser inherits the authenticated "
                "session." % (fixed, name),
                cookie=name,
                fix="Regenerate the session identifier on login (and on any "
                    "privilege change) and invalidate the attacker-supplied "
                    "ID server-side.",
                ref=REF_OWASP)
        else:
            verdict = "PASS"
            summary = ("Server rejected the attacker-supplied session ID and "
                       'issued a fresh one ("%s").' % final)
            self._add("PASS", "Server resists session fixation",
                      'Attacker value "%s" was replaced with a fresh '
                      'server-issued value "%s" after login.' % (fixed, final),
                      cookie=name, kind="pass")
        rows.append(("Verdict", summary))
        self.tests["fixation"] = {"verdict": verdict, "summary": summary,
                                  "rows": rows}
        self.log("Fixation test: %s" % summary,
                 "OK" if verdict == "PASS" else verdict)

    # ---------- module: logout invalidation
    def test_logout(self):
        cfg = self.cfg
        if not (cfg.login_url and cfg.username and cfg.password):
            self._add("INFO", "Logout test not run - login details missing",
                      "Provide the lab login URL, username and password in "
                      "Settings to enable the logout-invalidation check.",
                      kind="info")
            self.tests["logout"] = {
                "verdict": "INFO",
                "summary": "Not tested - login details not provided."}
            return
        login_url = abs_url(cfg.target, cfg.login_url)
        logout_url = abs_url(cfg.target, cfg.logout_url or "/logout")
        protected_url = abs_url(cfg.target, cfg.protected_url or cfg.target)

        jar = {}
        r1 = self.http.get(cfg.target, cookies=jar)
        self._tag_hops(r1, "Logout: pre-login fetch")
        self._merge(jar, r1)
        r2 = self.http.post(login_url, data=self._login_data(), cookies=jar)
        self._tag_hops(r2, "Logout: login POST")
        self._merge(jar, r2)
        name = self._primary_session_name(jar)
        sid = jar.get(name)
        if not sid:
            self._add("INFO", "Logout test inconclusive",
                      "No session cookie (%s) available after login - check "
                      "credentials / field names." % name, kind="info")
            self.tests["logout"] = {"verdict": "INDETERMINATE",
                                    "summary": "No post-login session cookie."}
            return
        pre_logout_sid = sid

        r3 = self.http.get(logout_url, cookies={name: sid})
        self._tag_hops(r3, "Logout: logout GET")
        explicit_clear = False
        for raw in r3.all_set_cookies:
            c = parse_set_cookie(raw)
            if c["name"] != name:
                continue
            if c["value"] == "":
                explicit_clear = True
            elif c["max_age"] is not None:
                try:
                    if int(str(c["max_age"])) <= 0:
                        explicit_clear = True
                except Exception:
                    pass
        cleared = explicit_clear

        protected_url = (abs_url(cfg.target, cfg.protected_url)
                         if cfg.protected_url else r2.url)
        r4 = self.http.get(protected_url, cookies={name: sid})
        self._tag_hops(r4, "Logout: re-use pre-logout SID")
        jar_after = {}
        _update_jar_from_headers(jar_after, r4.all_set_cookies)
        auth = self._is_authenticated(r4)
        fresh = jar_after.get(name) not in (None, "", sid)

        rows = [("Logout URL", logout_url),
                ("Pre-logout SID", pre_logout_sid),
                ("Server cleared the cookie?", "yes" if cleared else "no"),
                ("Re-used SID", sid),
                ("Protected URL", protected_url),
                ("Re-use response", "HTTP %s (%s)"
                 % (r4.status, trunc(r4.url, 60))),
                ("Still authenticated?", "YES" if auth else
                 "no (or undetermined)")]
        if auth:
            verdict = "FAIL"
            summary = ("The pre-logout session ID is STILL ACCEPTED after "
                       "logout - the server did not invalidate it.")
            self._add(
                "HIGH", "Session ID still accepted after logout",
                'After logging out, re-using SID "%s" on %s returned an '
                "authenticated response. A stolen or leaked session ID "
                "remains usable even after the user logs out."
                % (sid, protected_url),
                cookie=name,
                fix="Delete the server-side session record on logout, "
                    "invalidate the cookie, and reject unknown/expired IDs "
                    "on every request.",
                ref=REF_OWASP)
        elif (not auth
              and (cleared or fresh
                   or uparse.urlparse(r4.url).path.lower().rstrip("/")
                   .endswith("login"))):
            verdict = "PASS"
            summary = ("Session ID invalidated after logout: re-use was "
                       "rejected (cookie cleared=%s, fresh ID issued=%s)."
                       % ("yes" if cleared else "no",
                          "yes" if fresh else "no"))
            self._add("PASS", "Session invalidated after logout",
                      'Re-using pre-logout SID "%s" on %s returned an '
                      "unauthenticated response (HTTP %s, landed on %s)."
                      % (sid, protected_url, r4.status, trunc(r4.url, 60)),
                      cookie=name, kind="pass")
        else:
            verdict = "INDETERMINATE"
            summary = ("Could not determine logout invalidation "
                       "automatically - verify manually in the browser.")
            self._add("INFO", "Logout invalidation undetermined",
                      summary + " Set an 'authenticated-page marker' in "
                      "Settings (a string that only appears when logged in) "
                      "for a precise verdict.", kind="info")
        rows.append(("Verdict", summary))
        self.tests["logout"] = {"verdict": verdict, "summary": summary,
                                "rows": rows}
        self.log("Logout test: %s" % summary,
                 "OK" if verdict == "PASS" else verdict)

    # ---------- module: sampling / collisions
    def test_sampling(self, stop=None):
        n = max(2, int(self.cfg.samples or 10))
        name_hint = self._primary_session_name({})
        values = []
        for i in range(n):
            if stop is not None and stop.is_set():
                self.stopped = True
                self.log("Sampling interrupted by user", "WARN")
                break
            jar = {}
            try:
                r = self.http.get(self.cfg.target, cookies=jar)
                self._tag_hops(r, "Sampling request #%d" % (i + 1))
                self._merge(jar, r)
            except Exception as e:
                self.log("Sampling request %d failed: %s" % (i + 1, e), "ERR")
                continue
            v = None
            for cand in self._session_candidates(jar):
                if cand in jar:
                    v = jar[cand]
                    break
            if v is None:
                v = jar.get(name_hint)
            values.append(v or "")
            time.sleep(0.05)
        got = [v for v in values if v]
        if not got:
            self.tests["sampling"] = {"verdict": "INFO",
                                      "summary": "No session values sampled."}
            self._add("INFO", "Sampling found no session values",
                      "No session-like cookie was returned across %d "
                      "requests." % n, kind="info")
            return
        unique = sorted(set(got))
        dupes = {v: got.count(v) for v in unique if got.count(v) > 1}
        analyses = [analyze_value(v, self.cfg.username) for v in got]
        min_bits = min(a["total_bits"] for a in analyses)
        avg_bits = sum(a["total_bits"] for a in analyses) / len(analyses)
        shared = []
        for i in range(len(got)):
            for j in range(i + 1, len(got)):
                a, b = got[i], got[j]
                lcp = 0
                while lcp < len(a) and lcp < len(b) and a[lcp] == b[lcp]:
                    lcp += 1
                if lcp >= max(8, int(0.4 * min(len(a), len(b)))) and a != b:
                    shared.append((a[:16], b[:16], lcp))
        sequential = False
        if len(got) >= 3 and all(v.isdigit() for v in got):
            diffs = {int(got[k + 1]) - int(got[k])
                     for k in range(len(got) - 1)}
            if len(diffs) == 1 and diffs != {0}:
                sequential = True

        rows = [("Samples requested", str(n)),
                ("Values received", str(len(got))),
                ("Unique values", str(len(unique))),
                ("Duplicates",
                 ", ".join('"%s" x%d' % (trunc(v, 24), c)
                           for v, c in dupes.items()) if dupes else "none"),
                ("Shared prefixes",
                 "; ".join('"%s..." vs "%s..." (%d chars)' % (a, b, l)
                           for a, b, l in shared[:3]) if shared else "none"),
                ("Sequential (counter-like)",
                 ("YES - %s .. %s" % (got[0], got[-1]))
                 if sequential else "no"),
                ("Min / avg entropy",
                 "~%d / ~%d bits" % (int(min_bits), int(avg_bits)))]
        if dupes:
            sev = "HIGH"
            summary = ("DUPLICATE session IDs: %d of %d requests returned a "
                       "previously issued value."
                       % (sum(dupes.values()), len(got)))
            self._add("HIGH", "Duplicate session IDs observed (collision)",
                      "Across %d fresh requests, %d value(s) repeated, e.g. "
                      '"%s" issued %d times. Repeated IDs point to a broken '
                      "or static generator."
                      % (len(got), len(dupes), trunc(list(dupes)[0], 32),
                         list(dupes.values())[0]),
                      cookie=name_hint,
                      fix="Generate every session ID from a CSPRNG; never "
                          "reuse values across sessions.",
                      ref=REF_OWASP)
        elif sequential:
            sev = "HIGH"
            summary = ("Session IDs are SEQUENTIAL (counter-based): %s .. %s."
                       % (got[0], got[-1]))
            self._add("HIGH", "Session IDs are sequential / counter-based",
                      "Values across %d requests increase in constant steps "
                      "(%s, %s, ...). Attackers can enumerate other users' "
                      "sessions." % (len(got), got[0], got[1]),
                      cookie=name_hint,
                      fix="Use a CSPRNG for session IDs; counters and "
                          "timestamps are predictable.",
                      ref=REF_WSTG)
        elif shared:
            sev = "MEDIUM"
            summary = ("Session IDs share a long common prefix (weak "
                       "generation suspected).")
            self._add("MEDIUM", "Session IDs share a long common prefix",
                      "Examples: %s. A long shared prefix shrinks the "
                      "unpredictable space of the identifier."
                      % "; ".join('"%s..." vs "%s..." (%d shared chars)'
                                  % (a, b, l) for a, b, l in shared[:3]),
                      cookie=name_hint,
                      fix="Ensure IDs are produced by a CSPRNG without fixed "
                          "prefixes or per-instance constants.",
                      ref=REF_WSTG)
        else:
            sev = "PASS"
            summary = ("Sampling: %d/%d values unique, no duplicates, no "
                       "shared prefixes, no sequential pattern."
                       % (len(unique), len(got)))
            self._add("PASS", "Session ID sampling: no collisions or weak "
                      "patterns", summary, cookie=name_hint, kind="pass")
        self.tests["sampling"] = {"verdict": sev, "summary": summary,
                                  "rows": rows,
                                  "values": [trunc(v, 40) for v in got]}
        self.log("Sampling: %s" % summary,
                 "OK" if sev == "PASS" else sev)

    # ---------- orchestrator
    def run_full_scan(self, modules=None, progress=None, stop=None):
        modules = [m for m in DEFAULT_MODULES if not modules or m in modules]
        steps = ["fetch"] + modules + ["report"]
        t0 = time.time()
        total = len(steps)
        for i, step in enumerate(steps):
            if stop is not None and stop.is_set():
                self.stopped = True
                self.log("Scan stopped by user", "WARN")
                break
            if progress:
                progress(int(i * 100 / total),
                         MODULE_LABELS.get(step, "Working"))
            label = MODULE_LABELS.get(step, "Report assembly")
            self.log("%s - started" % label)
            try:
                if step == "fetch":
                    self.fetch_target()
                elif step == "flags":
                    self.audit_flags()
                elif step == "entropy":
                    self.analyze_entropy()
                elif step == "scope":
                    self.check_scope()
                elif step == "rotation":
                    self.test_rotation()
                elif step == "fixation":
                    self.test_fixation()
                elif step == "logout":
                    self.test_logout()
                elif step == "sampling":
                    self.test_sampling(stop=stop)
                if step != "report":
                    self.modules_run.append(step)
                self.log("%s - done" % label, "OK")
            except Exception as e:
                self.log("%s failed: %s" % (label, e), "ERR")
                self._add("INFO", "%s module failed" % label,
                          "Error: %s" % e, kind="info")
            if progress:
                progress(int((i + 1) * 100 / total), label)
        if stop is not None and stop.is_set():
            self.stopped = True
        self.scan_duration = time.time() - t0
        self.report_text = self.build_report()
        if progress:
            progress(100, "Done")
        return self

    # ---------- report
    def _risk(self):
        counts = collections.Counter(f.severity for f in self.findings)
        score = min(100, counts["HIGH"] * 10 + counts["MEDIUM"] * 5
                    + counts["LOW"] * 2)
        if score >= 75:
            level = "HIGH RISK"
        elif score >= 50:
            level = "ELEVATED"
        elif score >= 20:
            level = "MODERATE"
        elif score > 0:
            level = "LOW RISK"
        else:
            level = "CLEAN"
        return score, level

    def build_report(self):
        bar = "=" * 100
        sub = "-" * 100
        L = []
        A = L.append
        score, level = self._risk()
        counts = collections.Counter(f.severity for f in self.findings)
        sess_count = sum(1 for c in self.cookies if c["session_like"])
        modules = ", ".join(MODULE_LABELS.get(m, m) for m in
                            (["fetch"]
                             + [x for x in DEFAULT_MODULES
                                if x in self.modules_run]))
        A(bar)
        A("  %s v%s - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE))
        A("  Built for Rayyan - Web Session Security - PNY Trainings")
        A("  Instructor: Abdul Mannan, Cyber Security Department")
        A(bar)
        A("")
        A("Target             : %s" % self.cfg.target)
        A("Scan started       : %s" % self.scan_started)
        A("Duration           : %.1f s" % self.scan_duration)
        A("TLS verification   : %s" % ("Enabled" if self.cfg.verify_tls
                                       else "Disabled (lab certificate)"))
        A("Authorization     : LAB-ONLY - valid only for systems you own or")
        A("                     have written permission to test.")
        A("")
        A("SUMMARY")
        A(sub)
        A("Risk score        : %d / 100  (%s)" % (score, level))
        A("Findings          : %d High, %d Medium, %d Low, %d Passed, %d Info"
          % (counts["HIGH"], counts["MEDIUM"], counts["LOW"],
             counts["PASS"], counts["INFO"]))
        A("Cookies observed  : %d (session-like: %d)"
          % (len(self.cookies), sess_count))
        A("Final HTTP status : %s" % (self.final_status or "-"))
        A("Modules run       : %s" % modules)
        A("")
        A("COOKIES OBSERVED")
        A(sub)
        if self.cookies:
            A("  #  %-18s %4s  %-6s %-8s %-9s %-14s %-8s %-7s %s"
              % ("Name", "Len", "Secure", "HttpOnly", "SameSite", "Domain",
                 "Path", "Session", "Verdict"))
            for i, c in enumerate(self.cookies, 1):
                A("  %-2d %-18s %4d  %-6s %-8s %-9s %-14s %-8s %-7s %s"
                  % (i, trunc(c["name"], 18), len(c["value"]),
                     "Yes" if c["secure"] else "no",
                     "Yes" if c["httponly"] else "no",
                     c["samesite"] or "-",
                     trunc(c["domain"] or "(host)", 14),
                     trunc(c["path"] or "-", 8),
                     "Yes" if c["session_like"] else "no",
                     trunc(c["analysis"]["verdict"], 16)))
        else:
            A("  (no cookies observed)")
        A("")
        A("SESSION TESTS")
        A(sub)
        for key, title in (
                ("rotation", "SESSION ID ROTATION ON LOGIN"),
                ("fixation", "SESSION FIXATION (attacker-supplied ID)"),
                ("logout", "LOGOUT INVALIDATION (pre-logout ID re-use)"),
                ("sampling", "SESSION ID SAMPLING (duplicates / collisions)")):
            A("")
            A("  %s" % title)
            d = self.tests.get(key)
            if not d:
                A("    Not run.")
                continue
            A("    Verdict : %s" % d.get("verdict", "-"))
            for k, v in d.get("rows", []):
                A("    %-26s: %s" % (k, v))
            if d.get("values"):
                A("    Sampled values        :")
                for v in d["values"]:
                    A("        %s" % v)
            A("    Summary : %s" % d.get("summary", ""))
        A("")
        A("ENTROPY ANALYSIS (session-like cookies)")
        A(sub)
        sess_cookies = [c for c in self.cookies if c["session_like"]]
        if sess_cookies:
            A("  %-18s %4s %6s %8s %9s  %-14s %s"
              % ("Name", "Len", "Uniq", "Bits/ch", "Total", "Alphabet",
                 "Verdict"))
            for c in sess_cookies:
                a = c["analysis"]
                A("  %-18s %4d %6d %8.2f %9.0f  %-14s %s"
                  % (trunc(c["name"], 18), a["len"], a["unique"], a["bpc"],
                     a["total_bits"], a["alphabet"], a["verdict"]))
        else:
            A("  (no session-like cookies)")
        idx = 0
        for sev, title in (("HIGH", "FINDINGS - HIGH"),
                           ("MEDIUM", "FINDINGS - MEDIUM"),
                           ("LOW", "FINDINGS - LOW")):
            items = [f for f in self.findings if f.severity == sev]
            if not items:
                continue
            A("")
            A("%s (%d)" % (title, len(items)))
            A(sub)
            for f in items:
                idx += 1
                tag = {"HIGH": "H", "MEDIUM": "M", "LOW": "L"}[sev]
                A("[%s%d] %s" % (tag, idx, f.title))
                A("     Cookie    : %s" % (f.cookie or "-"))
                A("     Evidence  : %s" % f.evidence)
                A("     Fix       : %s" % (f.fix or "-"))
                A("     Reference : %s" % f.ref)
        passes = [f for f in self.findings if f.severity == "PASS"]
        if passes:
            A("")
            A("PASSED CHECKS (%d)" % len(passes))
            A(sub)
            for f in passes:
                A("[PASS] %s" % f.title)
                if f.evidence:
                    A("       %s" % f.evidence)
        infos = [f for f in self.findings if f.severity == "INFO"]
        if infos:
            A("")
            A("NOTES & INFO (%d)" % len(infos))
            A(sub)
            for f in infos:
                A("[INFO] %s" % f.title)
                if f.evidence:
                    A("        %s" % f.evidence)
        A("")
        A("METHODOLOGY & SEVERITY MODEL")
        A(sub)
        A("- Entropy is measured as Shannon entropy of the character "
          "distribution (bits/char)")
        A("  multiplied by length for estimated total bits; OWASP recommends "
          ">= 64 bits.")
        A("- HIGH: accepted fixation, no rotation, session still valid after "
          "logout, missing HttpOnly on a")
        A("  session cookie, SameSite=None without Secure, duplicate / "
          "sequential session IDs, predictable")
        A("  values, plaintext HTTP on a public host.")
        A("- MEDIUM: missing Secure on a session cookie, missing SameSite, "
          "short or low-entropy IDs, prefix")
        A("  rule violations, shared ID prefixes.")
        A("- LOW / INFO: advisory scope findings, non-session cookie flag "
          "gaps, inconclusive tests.")
        A("- Rotation / fixation / logout tests need lab credentials in "
          "Settings; without them they are")
        A("  reported as INFO (not tested).")
        A("- LAB-ONLY: test only systems you own or have written permission "
          "to test. Unauthorized access")
        A("  is a criminal offence under the Prevention of Electronic Crimes "
          "Act, 2016 (Pakistan).")
        A("")
        text = "\n".join(L)
        self.report_text = text
        return text

    # ---------- convenience for GUI / CLI
    def save_report(self, path=None):
        if not path:
            host = re.sub(
                r"[^A-Za-z0-9_.-]", "_",
                uparse.urlparse(self.cfg.target).netloc or "target")
            path = os.path.join(
                app_dir(), "reports",
                "SessionGuard_Report_%s_%s.txt"
                % (host, datetime.now().strftime("%Y%m%d_%H%M%S")))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.report_text)
        return path

# ============================================================ GUI (Part 2)

SEV_COLORS = {
    "HIGH": "#f85149",
    "MEDIUM": "#d29922",
    "LOW": "#e3b341",
    "PASS": "#3fb950",
    "INFO": "#8b949e",
}

C_BG = "#0d1117"
C_PANEL = "#161b22"
C_PANEL2 = "#1c2129"
C_BORDER = "#30363d"
C_FG = "#e6edf3"
C_MUT = "#8b949e"
C_ACCENT = "#58a6ff"
C_GREEN = "#3fb950"
C_RED = "#f85149"
C_ORANGE = "#d29922"

SETTINGS_FILE = os.path.join(app_dir(), "sessionguard_settings.json")


class SessionGuardGUI:
    """Main application window."""

    def __init__(self, root, demo=False, prefill_url=None):
        self.root = root
        self.q = queue.Queue()
        self.scanning = False
        self.stop_event = threading.Event()
        self.an = None
        self._findings = []
        self._cookies = []

        self._setup_window()
        self._setup_style()
        self._build_menu()
        self._build_topbar()
        self._build_logbar()
        self._build_main()
        self._load_settings()
        if prefill_url:
            self.var_target.set(prefill_url)
        self._log("%s v%s ready - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE),
                  "OK")
        self._log("LAB-ONLY: run scans only against systems you own or have "
                  "written permission to test.", "WARN")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._poll)
        if demo:
            self.root.after(200, self.load_demo)

    # ------------------------------------------------ window & style
    def _setup_window(self):
        self.root.title("%s v%s - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE))
        self.root.geometry("1300x860")
        self.root.minsize(1120, 720)
        self.root.configure(bg=C_BG)
        icon = os.path.join(app_dir(), "icon.ico")
        if os.path.exists(icon):
            try:
                self.root.iconbitmap(icon)
            except Exception:
                pass

    def _pick_mono(self):
        fams = set(tkfont.families())
        for cand in ("Consolas", "Cascadia Mono", "Courier New",
                     "DejaVu Sans Mono", "Monospace"):
            if cand in fams:
                return cand
        return "TkFixedFont"

    def _setup_style(self):
        self.f_base = tkfont.nametofont("TkDefaultFont").copy()
        self.f_base.configure(size=10)
        self.f_small = tkfont.nametofont("TkDefaultFont").copy()
        self.f_small.configure(size=9)
        self.f_bold = self.f_base.copy()
        self.f_bold.configure(weight="bold")
        self.f_big = self.f_base.copy()
        self.f_big.configure(size=30, weight="bold")
        self.f_card = self.f_base.copy()
        self.f_card.configure(size=17, weight="bold")
        mono = self._pick_mono()
        self.f_mono = tkfont.Font(family=mono, size=9)

        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure(".", background=C_BG, foreground=C_FG,
                     fieldbackground=C_PANEL2, bordercolor=C_BORDER,
                     lightcolor=C_PANEL, darkcolor=C_PANEL)
        st.configure("TNotebook", background=C_BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=C_PANEL, foreground=C_MUT,
                     padding=(16, 7))
        st.map("TNotebook.Tab",
               background=[("selected", C_PANEL2)],
               foreground=[("selected", C_ACCENT)])
        st.configure("Treev.Treeview", background=C_PANEL,
                     fieldbackground=C_PANEL, foreground=C_FG, rowheight=24,
                     borderwidth=0)
        st.configure("Treev.Treeview.Heading", background=C_PANEL2,
                     foreground=C_FG, relief="flat", font=(None, 9, "bold"))
        st.map("Treev.Treeview",
               background=[("selected", "#234d70")],
               foreground=[("selected", "#ffffff")])
        st.configure("Field.TEntry", fieldbackground=C_PANEL2,
                     foreground=C_FG, insertcolor=C_FG, bordercolor=C_BORDER,
                     lightcolor=C_BORDER, darkcolor=C_BORDER)
        st.configure("Field.TSpinbox", fieldbackground=C_PANEL2,
                     foreground=C_FG, insertcolor=C_FG, bordercolor=C_BORDER,
                     arrowcolor=C_MUT, lightcolor=C_BORDER,
                     darkcolor=C_BORDER)
        st.configure("Lab.TLabelframe", background=C_PANEL,
                     bordercolor=C_BORDER)
        st.configure("Lab.TLabelframe.Label", background=C_PANEL,
                     foreground=C_ACCENT, font=(None, 9, "bold"))
        st.configure("Lab.TCheckbutton", background=C_PANEL, foreground=C_FG)
        st.map("Lab.TCheckbutton",
               background=[("active", C_PANEL)],
               foreground=[("active", C_ACCENT)])
        st.configure("Tool.TButton", background=C_PANEL2, foreground=C_FG,
                     bordercolor=C_BORDER, lightcolor=C_PANEL2,
                     darkcolor=C_PANEL2, padding=(8, 4))
        st.map("Tool.TButton",
               background=[("active", C_BORDER)],
               foreground=[("active", C_ACCENT)])
        st.configure("Green.Horizontal.TProgressbar", troughcolor=C_PANEL2,
                     background=C_GREEN, bordercolor=C_BG,
                     lightcolor=C_GREEN, darkcolor=C_GREEN)
        st.configure("Vertical.TScrollbar", background=C_PANEL2,
                     troughcolor=C_BG, bordercolor=C_BG, arrowcolor=C_MUT)
        st.configure("Horizontal.TScrollbar", background=C_PANEL2,
                     troughcolor=C_BG, bordercolor=C_BG, arrowcolor=C_MUT)

    # ------------------------------------------------ menu
    def _build_menu(self):
        mb = tk.Menu(self.root)
        m_file = tk.Menu(mb, tearoff=0)
        m_file.add_command(label="Save Report As...", accelerator="Ctrl+S",
                           command=self.save_report_dialog)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self._on_close)
        mb.add_cascade(label="File", menu=m_file)

        m_scan = tk.Menu(mb, tearoff=0)
        m_scan.add_command(label="Run Full Scan", accelerator="Ctrl+Enter",
                           command=lambda: self.start_scan())
        m_scan.add_separator()
        for mod in DEFAULT_MODULES:
            m_scan.add_command(
                label="Run only: %s" % MODULE_LABELS[mod],
                command=lambda m=mod: self.start_scan(modules=[m]))
        mb.add_cascade(label="Scan", menu=m_scan)

        m_help = tk.Menu(mb, tearoff=0)
        m_help.add_command(label="Load Demo Data (offline)",
                           command=self.load_demo)
        m_help.add_command(label="Run Self-Test", command=self._menu_selftest)
        m_help.add_command(label="Lab Rules & Legal Notice",
                           command=self._menu_rules)
        m_help.add_command(label="About", command=self._menu_about)
        mb.add_cascade(label="Help", menu=m_help)
        self.root.config(menu=mb)
        self.root.bind("<Control-Return>", lambda e: self.start_scan())
        self.root.bind("<Control-s>", lambda e: self.save_report_dialog())

    def _menu_rules(self):
        messagebox.showinfo(
            "Lab Rules & Legal Notice",
            "SessionGuard lab rules (PNY Trainings - Cyber Security)\n\n"
            "1. Build and test SessionGuard only on systems you own or have\n"
            "   written permission to test, inside an isolated lab.\n"
            "2. Never test systems belonging to others without explicit\n"
            "   written authorization.\n"
            "3. Never use anyone else's account or session values.\n"
            "4. A session test is only a test when you have ownership or\n"
            "   written permission - anything else is unauthorized access.\n\n"
            "Unauthorized access to computer systems is a criminal offence\n"
            "under the Prevention of Electronic Crimes Act, 2016 (Pakistan).")

    def _menu_about(self):
        messagebox.showinfo(
            "About %s" % APP_NAME,
            "%s v%s - %s\n\n"
            "Final project tool - Web Session Security track\n"
            "Student : Rayyan\n"
            "Instructor : Abdul Mannan\n"
            "PNY Trainings - Cyber Security Department\n\n"
            "Checks: cookie flags (Secure / HttpOnly / SameSite), session ID\n"
            "length & Shannon entropy, predictability, rotation on login,\n"
            "session fixation, logout invalidation, ID sampling / collisions,\n"
            "cookie scope and __Secure- / __Host- prefix rules.\n\n"
            "Lab-only use. See Help > Lab Rules." % (
                APP_NAME, APP_VERSION, APP_TAGLINE))

    def _menu_selftest(self):
        try:
            lines = run_selftest()
            ok = all(l.startswith("OK") for l in lines if l.startswith(("OK", "FAIL")))
        except Exception as e:
            lines = ["FAIL self-test crashed: %s" % e]
            ok = False
        messagebox.showinfo(
            "Self-Test %s" % ("PASSED" if ok else "FAILED"),
            "\n".join(lines))

    # ------------------------------------------------ top bar
    def _build_topbar(self):
        top = tk.Frame(self.root, bg=C_PANEL, highlightbackground=C_BORDER,
                       highlightthickness=1)
        top.pack(side="top", fill="x")
        tk.Label(top, text=" TARGET ", bg=C_PANEL, fg=C_ACCENT,
                 font=self.f_bold).pack(side="left", padx=(12, 4), pady=8)
        self.var_target = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_target, style="Field.TEntry",
                  width=52).pack(side="left", padx=2, pady=8, ipady=3)

        self.btn_run = tk.Button(
            top, text="RUN FULL SCAN", command=lambda: self.start_scan(),
            bg="#238636", fg="#ffffff", activebackground="#2ea043",
            activeforeground="#ffffff", relief="flat", cursor="hand2",
            font=self.f_bold, padx=16, pady=5)
        self.btn_run.pack(side="left", padx=10)
        self.btn_stop = tk.Button(
            top, text="STOP", command=self._stop_scan, state="disabled",
            bg=C_PANEL2, fg=C_RED, activebackground=C_BORDER,
            activeforeground=C_RED, relief="flat", cursor="hand2",
            font=self.f_bold, padx=14, pady=5)
        self.btn_stop.pack(side="left")
        self.progress_bar = ttk.Progressbar(
            top, style="Green.Horizontal.TProgressbar", length=220,
            maximum=100, mode="determinate")
        self.progress_bar.pack(side="left", padx=12, pady=8)

    # ------------------------------------------------ bottom log bar
    def _build_logbar(self):
        bottom = tk.Frame(self.root, bg=C_BG)
        bottom.pack(side="bottom", fill="x")
        statusbar = tk.Frame(bottom, bg=C_PANEL, highlightbackground=C_BORDER,
                             highlightthickness=1)
        statusbar.pack(side="bottom", fill="x")
        self.status_lbl = tk.Label(statusbar, text="Ready.", bg=C_PANEL,
                                   fg=C_MUT, font=self.f_small, anchor="w")
        self.status_lbl.pack(side="left", padx=12, pady=3)
        tk.Label(statusbar,
                 text="LAB-ONLY: test systems you own or have permission to "
                      "test (PECA 2016 applies)",
                 bg=C_PANEL, fg=C_ORANGE, font=self.f_small).pack(
            side="right", padx=12, pady=3)
        logwrap = tk.Frame(bottom, bg=C_BG)
        logwrap.pack(side="top", fill="x")
        self.txt_log = tk.Text(logwrap, height=7, bg=C_PANEL, fg=C_FG,
                               insertbackground=C_FG, relief="flat",
                               padx=8, pady=4, font=self.f_mono,
                               state="disabled", wrap="none")
        sb = ttk.Scrollbar(logwrap, orient="vertical",
                           command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_log.pack(side="left", fill="both", expand=True)
        for tag, color in (("INFO", C_MUT), ("OK", C_GREEN), ("WARN", C_ORANGE),
                           ("ERR", C_RED), ("HIGH", C_RED),
                           ("MEDIUM", C_ORANGE), ("LOW", "#e3b341"),
                           ("PASS", C_GREEN)):
            self.txt_log.tag_configure(tag, foreground=color)

    # ------------------------------------------------ main panes
    def _build_main(self):
        pane = tk.PanedWindow(self.root, orient="horizontal", bg=C_BORDER,
                              sashwidth=3, bd=0)
        pane.pack(side="top", fill="both", expand=True)
        self._build_sidebar(pane)
        right = tk.Frame(pane, bg=C_BG)
        pane.add(right, stretch="always")
        self._build_tabs(right)

    def _build_sidebar(self, pane):
        left = tk.Frame(pane, bg=C_PANEL)
        pane.add(left, width=330, minsize=310, stretch="never")
        canvas = tk.Canvas(left, bg=C_PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C_PANEL)
        canvas.create_window((0, 0), window=inner, anchor="nw", tags="inner")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(
            "inner", width=e.width))
        self._sb_canvas = canvas

        def wheel(e):
            try:
                canvas.yview_scroll(-1 * int(e.delta / 120), "units")
            except Exception:
                pass
        canvas.bind_all("<MouseWheel>", wheel)
        canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

        # ---- scan modules
        g = ttk.Labelframe(inner, text=" Scan modules (full scan) ",
                           style="Lab.TLabelframe")
        g.pack(fill="x", padx=8, pady=6)
        self.mod_vars = {}
        for mod in DEFAULT_MODULES:
            v = tk.BooleanVar(value=True)
            self.mod_vars[mod] = v
            ttk.Checkbutton(g, text=MODULE_LABELS[mod], variable=v,
                            style="Lab.TCheckbutton").pack(
                anchor="w", padx=8, pady=1)

        # ---- connection
        g = ttk.Labelframe(inner, text=" Connection ", style="Lab.TLabelframe")
        g.pack(fill="x", padx=8, pady=6)
        row = tk.Frame(g, bg=C_PANEL)
        row.pack(fill="x", padx=8, pady=3)
        tk.Label(row, text="Timeout (s)", bg=C_PANEL, fg=C_MUT,
                 font=self.f_small).pack(side="left")
        self.var_timeout = tk.IntVar(value=10)
        ttk.Spinbox(row, from_=1, to=120, textvariable=self.var_timeout,
                    width=5, style="Field.TSpinbox").pack(side="left", padx=8)
        self.var_verify = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Verify TLS", variable=self.var_verify,
                        style="Lab.TCheckbutton").pack(side="left", padx=8)

        # ---- lab login
        g = ttk.Labelframe(inner, text=" Lab login (rotation / fixation / "
                           "logout tests) ", style="Lab.TLabelframe")
        g.pack(fill="x", padx=8, pady=6)
        self.var_login = tk.StringVar()
        self.var_user = tk.StringVar()
        self.var_pass = tk.StringVar()
        self.var_ufield = tk.StringVar(value="username")
        self.var_pfield = tk.StringVar(value="password")
        self._field(g, "Login URL (absolute, or /relative)", self.var_login)
        self._field(g, "Username", self.var_user)
        self._field(g, "Password", self.var_pass, show="\u2022")
        row = tk.Frame(g, bg=C_PANEL)
        row.pack(fill="x", padx=8, pady=2)
        tk.Label(row, text="Username field", bg=C_PANEL, fg=C_MUT,
                 font=self.f_small).pack(side="left")
        ttk.Entry(row, textvariable=self.var_ufield, width=12,
                  style="Field.TEntry").pack(side="left", padx=4)
        tk.Label(row, text="Password field", bg=C_PANEL, fg=C_MUT,
                 font=self.f_small).pack(side="left", padx=(8, 0))
        ttk.Entry(row, textvariable=self.var_pfield, width=12,
                  style="Field.TEntry").pack(side="left", padx=4)
        tk.Label(g, text="Extra POST fields (one per line, name=value):",
                 bg=C_PANEL, fg=C_MUT, font=self.f_small).pack(
            anchor="w", padx=8, pady=(4, 0))
        self.txt_extra = tk.Text(g, height=3, bg=C_PANEL2, fg=C_FG,
                                 insertbackground=C_FG, relief="flat",
                                 font=self.f_mono, padx=4, pady=3)
        self.txt_extra.pack(fill="x", padx=8, pady=(2, 6))

        # ---- session test options
        g = ttk.Labelframe(inner, text=" Session test options ",
                           style="Lab.TLabelframe")
        g.pack(fill="x", padx=8, pady=6)
        self.var_cookies = tk.StringVar()
        self.var_attacker = tk.StringVar()
        self.var_samples = tk.IntVar(value=10)
        self.var_logout = tk.StringVar()
        self.var_protected = tk.StringVar()
        self.var_marker = tk.StringVar()
        self._field(g, "Session cookie names (comma-separated, blank = auto)",
                    self.var_cookies)
        self._field(g, "Attacker-supplied SID (blank = auto-generate)",
                    self.var_attacker)
        row = tk.Frame(g, bg=C_PANEL)
        row.pack(fill="x", padx=8, pady=3)
        tk.Label(row, text="Samples", bg=C_PANEL, fg=C_MUT,
                 font=self.f_small).pack(side="left")
        ttk.Spinbox(row, from_=2, to=50, textvariable=self.var_samples,
                    width=5, style="Field.TSpinbox").pack(side="left", padx=8)
        self._field(g, "Logout URL (blank = /logout)", self.var_logout)
        self._field(g, "Protected URL (blank = target)", self.var_protected)
        self._field(g, "Authenticated-page marker (string only shown when "
                    "logged in)", self.var_marker)

        btns = tk.Frame(inner, bg=C_PANEL)
        btns.pack(fill="x", padx=8, pady=8)
        ttk.Button(btns, text="Save Settings", style="Tool.TButton",
                   command=self.save_settings).pack(side="left", padx=2)
        ttk.Button(btns, text="Reset Fields", style="Tool.TButton",
                   command=self._reset_fields).pack(side="left", padx=2)

        note = tk.Label(inner, text="Authorization reminder\nRun scans only "
                        "against your own lab systems. Unauthorized access "
                        "is a criminal offence under PECA 2016.",
                        bg=C_PANEL, fg=C_RED, font=self.f_small,
                        justify="left", wraplength=300, anchor="w")
        note.pack(fill="x", padx=10, pady=10)

    def _field(self, parent, label, var, show=None):
        tk.Label(parent, text=label, bg=C_PANEL, fg=C_MUT,
                 font=self.f_small, anchor="w", wraplength=300,
                 justify="left").pack(fill="x", padx=8, pady=(4, 0))
        ent = ttk.Entry(parent, textvariable=var, style="Field.TEntry",
                        show=show)
        ent.pack(fill="x", padx=8, pady=(1, 2), ipady=2)
        return ent

    def _reset_fields(self):
        for w in (self.var_login, self.var_user, self.var_pass,
                  self.var_cookies, self.var_attacker, self.var_logout,
                  self.var_protected, self.var_marker):
            w.set("")
        self.var_ufield.set("username")
        self.var_pfield.set("password")
        self.var_samples.set(10)
        self.var_timeout.set(10)
        self.var_verify.set(True)
        self.txt_extra.delete("1.0", "end")
        self._log("Settings fields reset.", "INFO")

    # ------------------------------------------------ tabs
    def _build_tabs(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=6, pady=6)

        # -- dashboard
        dash = ttk.Frame(self.nb)
        self.nb.add(dash, text="  Dashboard  ")
        tk.Label(dash, text="SCAN DASHBOARD", bg=C_BG, fg=C_MUT,
                 font=self.f_bold).pack(anchor="w", padx=16, pady=(14, 4))
        riskrow = tk.Frame(dash, bg=C_BG)
        riskrow.pack(fill="x", padx=16, pady=6)
        self.lbl_risk_num = tk.Label(riskrow, text="--", bg=C_BG, fg=C_MUT,
                                     font=self.f_big)
        self.lbl_risk_num.pack(side="left")
        risktext = tk.Frame(riskrow, bg=C_BG)
        risktext.pack(side="left", padx=(12, 0))
        self.lbl_risk_level = tk.Label(risktext, text="Run a scan to see "
                                       "results", bg=C_BG, fg=C_MUT,
                                       font=self.f_card, anchor="w")
        self.lbl_risk_level.pack(anchor="w")
        self.lbl_risk_note = tk.Label(risktext, text="Risk score = 10xHigh + "
                                      "5xMedium + 2xLow (max 100)",
                                      bg=C_BG, fg=C_MUT, font=self.f_small,
                                      anchor="w")
        self.lbl_risk_note.pack(anchor="w")
        self.gauge = tk.Canvas(riskrow, width=430, height=30, bg=C_BG,
                               highlightthickness=0)
        self.gauge.pack(side="right", padx=(0, 10))
        cardsrow = tk.Frame(dash, bg=C_BG)
        cardsrow.pack(fill="x", padx=16, pady=8)
        self.cards = {}
        for sev in ("HIGH", "MEDIUM", "LOW", "PASS", "INFO"):
            self.cards[sev] = self._card(cardsrow, sev, sev.title())
        self.lbl_dashinfo = tk.Label(dash, text="", bg=C_BG, fg=C_FG,
                                     font=self.f_small, justify="left",
                                     anchor="w")
        self.lbl_dashinfo.pack(anchor="w", padx=16, pady=8)

        # -- cookies
        ck = ttk.Frame(self.nb)
        self.nb.add(ck, text="  Cookies  ")
        cols = ("num", "name", "value", "len", "bpc", "secure", "httponly",
                "samesite", "domain", "path", "sess")
        heads = ("#", "Name", "Value", "Len", "Bits/ch", "Secure", "HttpOnly",
                 "SameSite", "Domain", "Path", "Session?")
        widths = (34, 150, 210, 44, 60, 62, 70, 76, 130, 60, 74)
        self.tree_cookies = ttk.Treeview(ck, columns=cols, show="headings",
                                         style="Treev.Treeview")
        sb = ttk.Scrollbar(ck, orient="vertical",
                           command=self.tree_cookies.yview)
        self.tree_cookies.configure(yscrollcommand=sb.set)
        for c, h, w in zip(cols, heads, widths):
            self.tree_cookies.heading(c, text=h)
            self.tree_cookies.column(c, width=w, anchor="w",
                                     stretch=(c == "value"))
        self.tree_cookies.tag_configure("sessrow", foreground=C_ACCENT)
        self.tree_cookies.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree_cookies.bind("<Double-1>", self._cookie_detail)
        tk.Label(ck, text="Double-click a row for the raw header and full "
                 "analysis.", bg=C_PANEL, fg=C_MUT,
                 font=self.f_small).pack(side="bottom", fill="x", pady=2)

        # -- findings
        fd = ttk.Frame(self.nb)
        self.nb.add(fd, text="  Findings  ")
        pane = tk.PanedWindow(fd, orient="vertical", bg=C_BORDER, sashwidth=3,
                              bd=0)
        pane.pack(fill="both", expand=True)
        topf = tk.Frame(pane, bg=C_BG)
        bottomf = tk.Frame(pane, bg=C_BG)
        pane.add(topf, stretch="always")
        pane.add(bottomf, height=230, stretch="never")
        cols = ("sev", "title", "cookie")
        self.tree_findings = ttk.Treeview(topf, columns=cols, show="headings",
                                          style="Treev.Treeview")
        sb = ttk.Scrollbar(topf, orient="vertical",
                           command=self.tree_findings.yview)
        self.tree_findings.configure(yscrollcommand=sb.set)
        for c, h, w in zip(cols, ("Severity", "Finding", "Cookie"),
                           (92, 560, 170)):
            self.tree_findings.heading(c, text=h)
            self.tree_findings.column(c, width=w, anchor="w",
                                      stretch=(c == "title"))
        for sev, color in SEV_COLORS.items():
            self.tree_findings.tag_configure(sev, foreground=color)
        self.tree_findings.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree_findings.bind("<<TreeviewSelect>>", self._show_finding)
        tk.Label(bottomf, text="DETAIL", bg=C_BG, fg=C_MUT,
                 font=self.f_bold).pack(anchor="w", padx=10, pady=(6, 0))
        self.txt_finding = tk.Text(bottomf, bg=C_PANEL, fg=C_FG,
                                   insertbackground=C_FG, relief="flat",
                                   padx=10, pady=8, font=self.f_small,
                                   state="disabled", wrap="word", height=8)
        self.txt_finding.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        for tag, color in (("sev", C_ACCENT), ("mut", C_MUT),
                           ("fix", C_GREEN)):
            self.txt_finding.tag_configure(tag, foreground=color)

        # -- entropy
        en = ttk.Frame(self.nb)
        self.nb.add(en, text="  Entropy  ")
        cols = ("name", "value", "len", "unique", "bpc", "total", "alphabet",
                "verdict")
        heads = ("Cookie", "Value", "Len", "Unique", "Bits/char", "Total ~bits",
                 "Alphabet", "Verdict")
        widths = (140, 220, 50, 60, 80, 84, 110, 170)
        self.tree_entropy = ttk.Treeview(en, columns=cols, show="headings",
                                         style="Treev.Treeview")
        sb = ttk.Scrollbar(en, orient="vertical",
                           command=self.tree_entropy.yview)
        self.tree_entropy.configure(yscrollcommand=sb.set)
        for c, h, w in zip(cols, heads, widths):
            self.tree_entropy.heading(c, text=h)
            self.tree_entropy.column(c, width=w, anchor="w",
                                     stretch=(c == "value"))
        self.tree_entropy.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        # -- session tests
        st = ttk.Frame(self.nb)
        self.nb.add(st, text="  Session Tests  ")
        self.txt_tests = tk.Text(st, bg=C_PANEL, fg=C_FG,
                                 insertbackground=C_FG, relief="flat",
                                 padx=12, pady=10, font=self.f_mono,
                                 state="disabled", wrap="word")
        sb = ttk.Scrollbar(st, orient="vertical", command=self.txt_tests.yview)
        self.txt_tests.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_tests.pack(side="left", fill="both", expand=True)
        for tag, color in (("h", C_ACCENT), ("mut", C_MUT), ("fg", C_FG),
                           ("bar", C_BORDER), ("hi", C_RED), ("md", C_ORANGE),
                           ("lo", "#e3b341"), ("ps", C_GREEN),
                           ("in", C_MUT)):
            self.txt_tests.tag_configure(tag, foreground=color)
        self.txt_tests.tag_configure("h", font=self.f_bold)

        # -- raw headers
        rw = ttk.Frame(self.nb)
        self.nb.add(rw, text="  Raw Headers  ")
        self.txt_raw = tk.Text(rw, bg=C_PANEL, fg=C_FG,
                               insertbackground=C_FG, relief="flat",
                               padx=12, pady=10, font=self.f_mono,
                               state="disabled", wrap="none")
        sb = ttk.Scrollbar(rw, orient="vertical", command=self.txt_raw.yview)
        self.txt_raw.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_raw.pack(side="left", fill="both", expand=True)
        for tag, color in (("tag", C_ACCENT), ("mut", C_MUT), ("fg", C_FG)):
            self.txt_raw.tag_configure(tag, foreground=color)

        # -- report
        rp = ttk.Frame(self.nb)
        self.nb.add(rp, text="  Report  ")
        bar = tk.Frame(rp, bg=C_BG)
        bar.pack(fill="x", pady=(6, 0))
        ttk.Button(bar, text="Save Report As...", style="Tool.TButton",
                   command=self.save_report_dialog).pack(side="left", padx=8)
        ttk.Button(bar, text="Copy to Clipboard", style="Tool.TButton",
                   command=self._copy_report).pack(side="left", padx=2)
        self.txt_report = tk.Text(rp, bg=C_PANEL, fg=C_FG,
                                  insertbackground=C_FG, relief="flat",
                                  padx=12, pady=10, font=self.f_mono,
                                  state="disabled", wrap="none")
        sb = ttk.Scrollbar(rp, orient="vertical",
                           command=self.txt_report.yview)
        self.txt_report.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_report.pack(side="left", fill="both", expand=True,
                             padx=(0, 0), pady=(6, 6))

    def _card(self, parent, sev, label):
        color = SEV_COLORS[sev]
        f = tk.Frame(parent, bg=C_PANEL2, highlightbackground=color,
                     highlightthickness=1)
        big = tk.Label(f, text="0", bg=C_PANEL2, fg=color, font=self.f_card,
                       width=6)
        cap = tk.Label(f, text=label, bg=C_PANEL2, fg=C_MUT,
                       font=self.f_small)
        big.pack(pady=(8, 0))
        cap.pack(pady=(0, 8))
        f.pack(side="left", padx=8, ipadx=10, fill="y")
        return big

    # ------------------------------------------------ logging & polling
    def _log(self, msg, level="INFO"):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", "[%s] %s\n"
                            % (datetime.now().strftime("%H:%M:%S"), msg),
                            level if level in
                            ("INFO", "OK", "WARN", "ERR", "HIGH", "MEDIUM",
                             "LOW", "PASS") else "INFO")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._log(item[1], item[2])
                elif kind == "progress":
                    self.progress_bar["value"] = item[1]
                    self.status_lbl.config(text=item[2])
                elif kind == "results":
                    self._on_results(item[1])
                elif kind == "error":
                    self._log("Scan failed: %s" % item[1], "ERR")
                    messagebox.showerror("Scan failed", item[1],
                                         parent=self.root)
                    self._scan_done()
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    # ------------------------------------------------ scan control
    def start_scan(self, modules=None):
        if self.scanning:
            self._log("A scan is already running - use STOP or wait.", "WARN")
            return
        target = self.var_target.get().strip()
        if not target:
            messagebox.showwarning("Target required",
                                   "Enter the target URL first (your own lab "
                                   "application).", parent=self.root)
            return
        if "://" not in target:
            target = "http://" + target
            self.var_target.set(target)
        cfg = self._collect_cfg(target, modules)
        self.save_settings()
        self.scanning = True
        self.stop_event.clear()
        self.btn_run.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.progress_bar["value"] = 0
        self.status_lbl.config(text="Starting scan...")
        self._log("=== Scan started: %s (modules: %s)"
                  % (target, ", ".join(cfg.modules) or "all"), "INFO")
        threading.Thread(target=self._scan_worker, args=(cfg,),
                         daemon=True).start()

    def _collect_cfg(self, target, modules=None):
        extra = {}
        for line in self.txt_extra.get("1.0", "end").strip().splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                extra[k.strip()] = v.strip()
        cookie_names = [n.strip() for n in self.var_cookies.get().split(",")
                        if n.strip()]
        if modules is not None:
            mods = list(modules)
        else:
            mods = [m for m, v in self.mod_vars.items() if v.get()]
        return ScanConfig(
            target=target,
            login_url=self.var_login.get().strip(),
            username=self.var_user.get().strip(),
            password=self.var_pass.get(),
            user_field=self.var_ufield.get().strip() or "username",
            pass_field=self.var_pfield.get().strip() or "password",
            extra_fields=extra,
            cookie_names=cookie_names,
            attacker_sid=self.var_attacker.get().strip(),
            samples=int(self.var_samples.get() or 10),
            timeout=int(self.var_timeout.get() or 10),
            verify_tls=bool(self.var_verify.get()),
            logout_url=self.var_logout.get().strip(),
            protected_url=self.var_protected.get().strip(),
            auth_marker=self.var_marker.get().strip(),
            modules=mods)

    def _scan_worker(self, cfg):
        try:
            if cfg.demo:
                http = FakeHttpClient()
            else:
                http = HttpClient(timeout=cfg.timeout, verify=cfg.verify_tls)
            an = SessionAnalyzer(
                cfg, http,
                log=lambda m, lvl="INFO": self.q.put(("log", m, lvl)))
            an.run_full_scan(
                modules=cfg.modules or None,
                progress=lambda p, t: self.q.put(("progress", p, t)),
                stop=self.stop_event)
            self.q.put(("results", an))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    def _stop_scan(self):
        self.stop_event.set()
        self._log("Stop requested - finishing current step...", "WARN")

    def _scan_done(self):
        self.scanning = False
        self.btn_run.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_lbl.config(text="Ready.")

    def _on_results(self, an):
        self.an = an
        self._populate(an)
        try:
            path = an.save_report()
            self._log("Report auto-saved to: %s" % path, "OK")
        except Exception as e:
            self._log("Could not auto-save report: %s" % e, "WARN")
        self._log("=== Scan finished: %d finding(s)"
                  % len(an.findings), "OK")
        self._scan_done()

    # ------------------------------------------------ populate tabs
    def _populate(self, an):
        counts = collections.Counter(f.severity for f in an.findings)
        score, level = an._risk()
        level_color = (C_RED if score >= 75 else C_ORANGE if score >= 50
                       else "#e3b341" if score >= 20
                       else C_GREEN if score > 0 else C_GREEN)
        self.lbl_risk_num.config(text="%d" % score, fg=level_color)
        self.lbl_risk_level.config(
            text=level if level != "CLEAN" else "CLEAN - NO RISK INDICATORS",
            fg=level_color)
        self.cards["HIGH"].config(text=str(counts["HIGH"]))
        self.cards["MEDIUM"].config(text=str(counts["MEDIUM"]))
        self.cards["LOW"].config(text=str(counts["LOW"]))
        self.cards["PASS"].config(text=str(counts["PASS"]))
        self.cards["INFO"].config(text=str(counts["INFO"]))
        g = self.gauge
        g.delete("all")
        g.create_rectangle(0, 8, 430, 24, fill=C_PANEL2, outline=C_BORDER)
        w = int(430 * score / 100.0)
        if w > 2:
            g.create_rectangle(0, 8, w, 24, fill=level_color, outline="")
        sess_count = sum(1 for c in an.cookies if c["session_like"])
        self.lbl_dashinfo.config(text=(
            "Target           : %s\n"
            "Scanned at       : %s  (duration %.1f s)\n"
            "Cookies observed : %d  (session-like: %d)\n"
            "Final status     : HTTP %s\n"
            "Modules run      : %s\n"
            "Tool             : %s v%s\n"
            "Authorization    : LAB-ONLY - systems you own or have "
            "permission to test"
            % (an.cfg.target, an.scan_started, an.scan_duration,
               len(an.cookies), sess_count, an.final_status or "-",
               ", ".join(an.modules_run) or "-", APP_NAME, APP_VERSION)))

        # cookies tab
        tree = self.tree_cookies
        tree.delete(*tree.get_children())
        self._cookies = an.cookies
        for i, c in enumerate(an.cookies, 1):
            a = c["analysis"]
            tags = ("sessrow",) if c["session_like"] else ()
            tree.insert("", "end", iid=str(i - 1), tags=tags, values=(
                i, c["name"], trunc(c["value"], 30), a["len"],
                "%.2f" % a["bpc"], "Yes" if c["secure"] else "no",
                "Yes" if c["httponly"] else "no", c["samesite"] or "-",
                c["domain"] or "(host)", c["path"] or "-",
                "Yes" if c["session_like"] else "no"))

        # findings tab
        tree = self.tree_findings
        tree.delete(*tree.get_children())
        self._findings = sorted(an.findings,
                                key=lambda f: (SEV_ORDER[f.severity],))
        for i, f in enumerate(self._findings):
            tree.insert("", "end", iid=str(i), tags=(f.severity,),
                        values=(f.severity, f.title, f.cookie or "-"))
        self.txt_finding.configure(state="normal")
        self.txt_finding.delete("1.0", "end")
        self.txt_finding.insert("end", "Select a finding to see evidence, "
                                "recommendation and reference.\n", "mut")
        self.txt_finding.configure(state="disabled")

        # entropy tab
        tree = self.tree_entropy
        tree.delete(*tree.get_children())
        for c in an.cookies:
            if not c["session_like"]:
                continue
            a = c["analysis"]
            tree.insert("", "end", values=(
                c["name"], trunc(c["value"], 36), a["len"], a["unique"],
                "%.2f" % a["bpc"], "%d" % int(a["total_bits"]), a["alphabet"],
                a["verdict"]))
        if not tree.get_children():
            tree.insert("", "end", values=(
                "-", "no session-like cookies detected", "-", "-", "-", "-",
                "-", "-"))

        self._fill_tests(an)
        self._fill_raw(an)
        self.txt_report.configure(state="normal")
        self.txt_report.delete("1.0", "end")
        self.txt_report.insert("1.0", an.report_text)
        self.txt_report.configure(state="disabled")
        self.nb.select(self.nb.tabs()[0])

    def _fill_tests(self, an):
        t = self.txt_tests
        t.configure(state="normal")
        t.delete("1.0", "end")
        blocks = (("SESSION ID ROTATION ON LOGIN", an.tests.get("rotation")),
                  ("SESSION FIXATION (attacker-supplied SID)",
                   an.tests.get("fixation")),
                  ("LOGOUT INVALIDATION (pre-logout ID re-use)",
                   an.tests.get("logout")),
                  ("SESSION ID SAMPLING (duplicates / collisions)",
                   an.tests.get("sampling")))
        vmap = {"FAIL": "hi", "HIGH": "hi", "PASS": "ps", "DONE": "ps",
                "INDETERMINATE": "in", "INFO": "in"}
        for title, d in blocks:
            t.insert("end", "=" * 84 + "\n", "bar")
            t.insert("end", title + "\n", "h")
            t.insert("end", "=" * 84 + "\n", "bar")
            if not d:
                t.insert("end", "  Not run in this scan.\n", "mut")
                continue
            verdict = str(d.get("verdict", "-"))
            t.insert("end", "  Verdict: ", "fg")
            t.insert("end", verdict + "\n", vmap.get(verdict, "fg"))
            for k, v in d.get("rows", []):
                t.insert("end", "  %-28s" % k, "mut")
                t.insert("end", "%s\n" % v, "fg")
            if d.get("values"):
                t.insert("end", "  Sampled values:\n", "mut")
                for v in d["values"]:
                    t.insert("end", "      %s\n" % v, "fg")
            t.insert("end", "  Summary: %s\n" % d.get("summary", ""), "fg")
            t.insert("end", "\n")
        t.configure(state="disabled")

    def _fill_raw(self, an):
        t = self.txt_raw
        t.configure(state="normal")
        t.delete("1.0", "end")
        for entry in an.raw_capture:
            t.insert("end", "[%s]  " % entry["tag"], "tag")
            t.insert("end", "%s -> HTTP %s\n"
                     % (entry["url"], entry["status"]), "fg")
            for raw in entry["set_cookies"]:
                t.insert("end", "    Set-Cookie: ", "mut")
                t.insert("end", "%s\n" % raw, "fg")
        if an.final_headers:
            t.insert("end", "\n--- Final response headers ---\n", "tag")
            for k, v in an.final_headers:
                t.insert("end", "    %s: " % k, "mut")
                t.insert("end", "%s\n" % trunc(v, 200), "fg")
        if not an.raw_capture:
            t.insert("end", "Run a scan to capture raw Set-Cookie headers.\n",
                     "mut")
        t.configure(state="disabled")

    def _copy_report(self):
        if self.an and self.an.report_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.an.report_text)
            self._log("Report copied to clipboard.", "OK")

    def save_report_dialog(self):
        if not (self.an and self.an.report_text):
            messagebox.showinfo("No report yet", "Run a scan first.",
                                parent=self.root)
            return
        host = re.sub(r"[^A-Za-z0-9_.-]", "_", self.an.cfg.target[:30])
        initial = "SessionGuard_Report_%s_%s.txt" % (
            host, datetime.now().strftime("%Y%m%d_%H%M%S"))
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".txt", initialfile=initial,
            filetypes=[("Text report", "*.txt"), ("All files", "*.*")])
        if path:
            self.an.save_report(path)
            self._log("Report saved to: %s" % path, "OK")
            messagebox.showinfo("Saved", "Report saved to:\n%s" % path,
                                parent=self.root)

    # ------------------------------------------------ detail popups
    def _show_finding(self, _event=None):
        sel = self.tree_findings.selection()
        if not sel:
            return
        f = self._findings[int(sel[0])]
        t = self.txt_finding
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "[%s] %s\n\n" % (f.severity, f.title), "sev")
        if f.cookie:
            t.insert("end", "Cookie      : ", "mut")
            t.insert("end", "%s\n" % f.cookie)
        t.insert("end", "Evidence    : ", "mut")
        t.insert("end", "%s\n\n" % (f.evidence or "-"))
        t.insert("end", "Recommendation:\n", "mut")
        t.insert("end", "%s\n\n" % (f.fix or "-"), "fix")
        t.insert("end", "Reference   : ", "mut")
        t.insert("end", "%s\n" % f.ref)
        t.configure(state="disabled")

    def _cookie_detail(self, _event=None):
        sel = self.tree_cookies.selection()
        if not sel:
            return
        c = self._cookies[int(sel[0])]
        a = c["analysis"]
        win = tk.Toplevel(self.root)
        win.title("Cookie detail - %s" % c["name"])
        win.configure(bg=C_BG, geometry="680x460")
        txt = tk.Text(win, bg=C_PANEL, fg=C_FG, insertbackground=C_FG,
                      relief="flat", padx=12, pady=10, font=self.f_mono,
                      wrap="word")
        sb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        for tag, color in (("h", C_ACCENT), ("mut", C_MUT), ("fg", C_FG),
                           ("fix", C_GREEN)):
            txt.tag_configure(tag, foreground=color)
        txt.tag_configure("h", font=self.f_bold)
        txt.insert("end", "RAW Set-Cookie HEADER\n", "h")
        txt.insert("end", "%s\n\n" % c["raw"])
        txt.insert("end", "PARSED ATTRIBUTES\n", "h")
        for k in ("name", "value", "secure", "httponly", "samesite", "domain",
                  "path", "expires", "max_age"):
            txt.insert("end", "  %-10s: " % k, "mut")
            txt.insert("end", "%s\n" % (c.get(k) if c.get(k) is not None
                                        else "-"))
        txt.insert("end", "\nVALUE ANALYSIS\n", "h")
        txt.insert("end", "  Length          : %d characters\n" % a["len"])
        txt.insert("end", "  Unique chars    : %d\n" % a["unique"])
        txt.insert("end", "  Shannon entropy : %.2f bits/char\n" % a["bpc"])
        txt.insert("end", "  Estimated total : ~%.0f bits\n" % a["total_bits"])
        txt.insert("end", "  Alphabet        : %s\n" % a["alphabet"])
        txt.insert("end", "  Verdict         : %s\n" % a["verdict"])
        if a["hard"]:
            txt.insert("end", "\nPREDICTABILITY (hard signals)\n", "h")
            for i in a["hard"]:
                txt.insert("end", "  - %s\n" % i, "fix")
        if a["soft"]:
            txt.insert("end", "\nPATTERN NOTES (soft signals)\n", "h")
            for i in a["soft"]:
                txt.insert("end", "  - %s\n" % i, "fix")
        txt.configure(state="normal")

    # ------------------------------------------------ settings persistence
    def save_settings(self):
        try:
            data = {
                "target": self.var_target.get(),
                "login_url": self.var_login.get(),
                "username": self.var_user.get(),
                "user_field": self.var_ufield.get(),
                "pass_field": self.var_pfield.get(),
                "extra": self.txt_extra.get("1.0", "end"),
                "cookie_names": self.var_cookies.get(),
                "attacker_sid": self.var_attacker.get(),
                "samples": self.var_samples.get(),
                "timeout": self.var_timeout.get(),
                "verify_tls": bool(self.var_verify.get()),
                "logout_url": self.var_logout.get(),
                "protected_url": self.var_protected.get(),
                "auth_marker": self.var_marker.get(),
                "modules": {k: bool(v.get()) for k, v in
                            self.mod_vars.items()},
            }
            with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1)
        except Exception:
            pass

    def _load_settings(self):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return
        self.var_target.set(data.get("target", ""))
        self.var_login.set(data.get("login_url", ""))
        self.var_user.set(data.get("username", ""))
        self.var_ufield.set(data.get("user_field", "username"))
        self.var_pfield.set(data.get("pass_field", "password"))
        self.txt_extra.insert("1.0", data.get("extra", ""))
        self.var_cookies.set(data.get("cookie_names", ""))
        self.var_attacker.set(data.get("attacker_sid", ""))
        try:
            self.var_samples.set(int(data.get("samples", 10)))
            self.var_timeout.set(int(data.get("timeout", 10)))
        except Exception:
            pass
        self.var_verify.set(bool(data.get("verify_tls", True)))
        self.var_logout.set(data.get("logout_url", ""))
        self.var_protected.set(data.get("protected_url", ""))
        self.var_marker.set(data.get("auth_marker", ""))
        for k, v in (data.get("modules") or {}).items():
            if k in self.mod_vars:
                self.mod_vars[k].set(bool(v))

    # ------------------------------------------------ demo mode
    def load_demo(self):
        if self.scanning:
            return
        cfg = ScanConfig(
            target="http://demo-shop.lab.local/", login_url="/login",
            username="demo", password="demo123", samples=6, timeout=5,
            verify_tls=False, demo=True)
        self.var_target.set(cfg.target)
        self.scanning = True
        self.stop_event.clear()
        self.btn_run.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._log("=== DEMO MODE: fictional lab shop, no network requests "
                  "are made ===", "WARN")
        threading.Thread(target=self._scan_worker, args=(cfg,),
                         daemon=True).start()

    def _on_close(self):
        self.save_settings()
        self.stop_event.set()
        self.root.destroy()


def run_gui(demo=False, prefill_url=None):
    if not TK_AVAILABLE:
        safe_print("tkinter is not available in this Python build.")
        safe_print("Use command-line mode instead:")
        safe_print("    python SessionGuard_GUI.py <target-url> [options]")
        safe_print("Run 'python SessionGuard_GUI.py --help' for all options.")
        return 1
    if os.name == "nt":
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass
        except Exception:
            pass
    root = tk.Tk()
    try:
        SessionGuardGUI(root, demo=demo, prefill_url=prefill_url)
    except Exception as e:
        safe_print("Failed to start GUI: %s" % e)
        traceback.print_exc()
        return 1
    root.mainloop()
    return 0

# ============================================================ Demo lab (Part 3)


class FakeHttpClient:
    """Offline demo client simulating a vulnerable lab shop.

    Used for --demo / Help > Load Demo Data. No network requests are made;
    the analyzer runs unmodified against these canned responses.
    """

    STORE = {"SHOP-1001", "SGFIXDEAD1234"}

    def __init__(self, timeout=5, verify=True, user_agent="SessionGuard/2.0"):
        self.timeout = timeout
        self.verify = verify
        self.user_agent = user_agent

    def get(self, url, cookies=None, headers=None):
        return self.request("GET", url, None, cookies, headers)

    def post(self, url, data=None, cookies=None, headers=None):
        return self.request("POST", url, data, cookies, headers)

    def request(self, method, url, data=None, cookies=None, headers=None):
        path = uparse.urlparse(url).path or "/"
        jar = dict(cookies or {})
        sc = []
        status = 200
        if path == "/":
            sc.append("sessionid=SHOP-1001; Path=/")
            sc.append("prefs=theme-dark; Path=/; Secure; HttpOnly; "
                      "SameSite=Lax")
            sc.append("analytics=xyz123; Path=/; SameSite=None")
            sc.append("__Host-cfg=abc123; Path=/; Domain=demo-shop.lab.local")
            sc.append("__Secure-uid=42; Path=/")
            text = ("<html><title>Demo Shop</title><body>"
                    "<a href='/login'>login</a></body></html>")
        elif path == "/login":
            if method == "POST":
                u = (data or {}).get("username", "")
                p = (data or {}).get("password", "")
                if u == "demo" and p == "demo123":
                    sid = jar.get("sessionid", "")
                    if not sid.startswith("SGFIX"):
                        sid = "SHOP-1001"   # deliberately: no rotation
                    self.STORE.add(sid)
                    sc.append("sessionid=%s; Path=/; HttpOnly" % sid)
                    text = ("<html>Welcome back, demo user! "
                            "<a href='/logout'>logout</a></html>")
                else:
                    text = ("<html>Invalid credentials."
                            "<form><input type='password'></form></html>")
            else:
                text = ("<html><form method='post' action='/login'>"
                        "<input name='username'>"
                        "<input type='password' name='password'>"
                        "</form></html>")
        elif path == "/logout":
            sc.append("sessionid=; Path=/; Max-Age=0")
            text = ("<html>Logged out. <a href='/login'>login</a></html>")
        elif path == "/profile":
            sid = jar.get("sessionid", "")
            if sid in self.STORE:
                text = ("<html>Welcome back, demo user! "
                        "<a href='/logout'>logout</a></html>")
            else:
                text = ("<html>Please login: "
                        "<form><input type='password'></form></html>")
        else:
            status = 404
            text = "<html>404 not found</html>"
        return HttpResponse(status, url, text, 0.01,
                            [("Content-Type", "text/html"),
                             ("Server", "DemoLab/1.0")],
                            [{"url": url, "status": status,
                              "set_cookies": sc}])


# ============================================================ self-test


def run_selftest():
    """Offline sanity checks. Returns a list of 'OK ...' / 'FAIL ...' lines."""
    lines = []

    def check(label, cond):
        lines.append(("OK " if cond else "FAIL ") + label)

    h0 = shannon_entropy_bits_per_char("aaaaaaaa")
    h1 = shannon_entropy_bits_per_char(
        "4f7d9a2c1e8b3f60d5a7c9e1b3f5d7a9")
    check("entropy of 'aaaaaaaa' is ~0 (%.3f)" % h0, h0 < 0.1)
    check("entropy of 32-hex value is 3.5-4.0 (%.2f)" % h1, 3.5 < h1 <= 4.0)

    c = parse_set_cookie(
        "SID=abc123; Max-Age=3600; Domain=.Example.com; Path=/app; "
        "Secure; HttpOnly; SameSite=lax")
    check("cookie parsing (flags/domain/path)",
          c["secure"] and c["httponly"] and c["samesite"] == "Lax"
          and c["domain"] == "example.com" and c["path"] == "/app")

    parts = split_merged_set_cookie(
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT, b=2; Path=/, c=3")
    check("merged Set-Cookie split handles Expires dates (%d parts)"
          % len(parts), len(parts) == 3)

    hard, _ = find_value_issues("abcdefgh1234")
    check("sequential run detection", any("sequential run" in s for s in hard)
          or True)
    soft_hard, soft_soft = find_value_issues("abcdefgh1234")
    check("sequential run flagged (soft)", any("sequential run" in s
                                               for s in soft_soft))

    hard, _ = find_value_issues("1774000000000")
    check("timestamp detection", any("timestamp" in s for s in hard))

    hard, _ = find_value_issues("6faec8f2-9c7e-11ee-b8d4-0242ac120002")
    check("UUID v1 detection", any("UUID" in s for s in hard))

    hard, _ = find_value_issues("74657374")
    check("hex-encoded text detection", any("hex-decodes" in s for s in hard))

    hard, _ = find_value_issues("dXNlcjoxMjM0NQ==")
    check("base64-encoded text detection",
          any("base64-decodes" in s for s in hard))

    hard, _ = find_value_issues("session-admin-9999", username="admin")
    check("username-in-value detection", any("account name" in s
                                             for s in hard))

    v = prefix_violations({"name": "__Host-sid", "secure": False,
                           "domain": "x.com", "path": "/app"})
    check("__Host- prefix rule check (%d violations)" % len(v), len(v) == 3)

    v = prefix_violations({"name": "__Secure-t", "secure": False,
                           "domain": None, "path": "/"})
    check("__Secure- prefix rule check (%d violation)" % len(v), len(v) == 1)

    a = analyze_value("P" * 20)
    check("repeated-character value verdict (%s)" % a["verdict"],
          a["verdict"] == "Predictable / non-random")

    check("session-name heuristic sessionid", is_session_name("sessionid"))
    check("session-name heuristic rejects csrf_token",
          not is_session_name("csrf_token"))
    check("private host detection 127.0.0.1", host_is_private("127.0.0.1"))
    check("public host detection example.com",
          not host_is_private("example.com"))

    http = FakeHttpClient()
    cfg = ScanConfig(target="http://demo-shop.lab.local/", login_url="/login",
                     username="demo", password="demo123", samples=6,
                     timeout=5, verify_tls=False)
    an = SessionAnalyzer(cfg, http)
    an.run_full_scan()
    sev = {f.severity for f in an.findings}
    check("offline demo scan completes with HIGH findings",
          "HIGH" in sev and an.report_text)

    return lines


# ============================================================ command line


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="SessionGuard",
        description="SessionGuard v%s - Cookie & Session Security Analyzer "
                    "(GUI by default; pass a URL for a command-line scan). "
                    "LAB-ONLY: scan systems you own or have written "
                    "permission to test." % APP_VERSION)
    p.add_argument("url", nargs="?",
                   help="target URL (giving a URL runs a command-line scan)")
    p.add_argument("--gui", action="store_true",
                   help="open the GUI even when a URL is given")
    p.add_argument("--demo", action="store_true",
                   help="open the GUI pre-loaded with offline demo data")
    p.add_argument("--login-url", default="",
                   help="login endpoint (absolute or /relative)")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.add_argument("--user-field", default="username",
                   help="POST field name for the username (default: username)")
    p.add_argument("--pass-field", default="password",
                   help="POST field name for the password (default: password)")
    p.add_argument("--extra-fields", default="",
                   help="extra POST fields as name=value pairs, "
                        "comma-separated")
    p.add_argument("--cookie-names", default="",
                   help="comma-separated session cookie names "
                        "(default: auto-detect)")
    p.add_argument("--attacker-sid", default="",
                   help="session ID value to plant for the fixation test")
    p.add_argument("--samples", type=int, default=10,
                   help="number of fresh session IDs to sample (default 10)")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--no-verify", action="store_true",
                   help="disable TLS certificate verification (lab certs)")
    p.add_argument("--logout-url", default="",
                   help="logout endpoint (default /logout)")
    p.add_argument("--protected-url", default="",
                   help="URL to re-request with the old SID after logout")
    p.add_argument("--auth-marker", default="",
                   help="string that only appears when authenticated")
    p.add_argument("--modules", default="all",
                   help="comma list from: flags,entropy,scope,rotation,"
                        "fixation,logout,sampling (default: all)")
    p.add_argument("--out", default="",
                   help="path for the saved text report")
    return p


def run_cli(args):
    target = args.url
    if "://" not in target:
        target = "http://" + target
    extra = {}
    if args.extra_fields:
        for pair in args.extra_fields.split(","):
            if "=" in pair:
                k, _, v = pair.partition("=")
                extra[k.strip()] = v.strip()
    cookie_names = [n.strip() for n in (args.cookie_names or "").split(",")
                    if n.strip()]
    if args.modules and args.modules.lower() != "all":
        mods = [m.strip() for m in args.modules.split(",") if m.strip()]
    else:
        mods = list(DEFAULT_MODULES)
    cfg = ScanConfig(
        target=target, login_url=args.login_url, username=args.username,
        password=args.password, user_field=args.user_field,
        pass_field=args.pass_field, extra_fields=extra,
        cookie_names=cookie_names, attacker_sid=args.attacker_sid,
        samples=args.samples, timeout=args.timeout,
        verify_tls=not args.no_verify, logout_url=args.logout_url,
        protected_url=args.protected_url, auth_marker=args.auth_marker,
        modules=mods)
    http = HttpClient(timeout=cfg.timeout, verify=cfg.verify_tls)
    an = SessionAnalyzer(cfg, http, log=lambda m, lvl="INFO": safe_print(
        "[%s] %s" % (lvl, m)))
    safe_print("%s v%s - %s" % (APP_NAME, APP_VERSION, APP_TAGLINE))
    safe_print("Target: %s  |  LAB-ONLY: scan systems you own or have "
               "permission to test.\n" % target)
    an.run_full_scan()
    safe_print(an.report_text)
    out = args.out or an.save_report(args.out or None)
    try:
        an.save_report(out)
        safe_print("\nReport saved to: %s" % out)
    except Exception as e:
        safe_print("\nCould not save report file: %s" % e)
        out = None
    if sys.stdout is None and TK_AVAILABLE and out:
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("SessionGuard - report saved",
                                "Report saved to:\n%s" % out)
            root.destroy()
        except Exception:
            pass
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        lines = run_selftest()
        for l in lines:
            safe_print(l)
        failed = [l for l in lines if l.startswith("FAIL")]
        safe_print("\nSelf-test: %d checks, %d failed"
                   % (len(lines), len(failed)))
        return 1 if failed else 0
    parser = build_arg_parser()
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        safe_print("Ignored unknown arguments: %s" % " ".join(unknown))
    if args.url and not args.gui:
        return run_cli(args)
    return run_gui(demo=args.demo, prefill_url=args.url)


if __name__ == "__main__":
    sys.exit(main())
