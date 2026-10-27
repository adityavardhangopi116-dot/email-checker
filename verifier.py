"""Email deliverability checks: syntax -> DNS (MX) -> optional SMTP RCPT probe.

The SMTP probe opens a connection to the recipient's mail server and asks
"would you accept mail for this address?" (RCPT TO). It then disconnects
with RSET/QUIT *before* the DATA command, so no message is ever sent.
"""
import os
import random
import re
import smtplib
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import dns.exception
import dns.resolver

DELIVERABLE, BOUNCE, UNKNOWN = "deliverable", "bounce", "unknown"

LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SPLIT_RE = re.compile(r"[\s,;]+")
POLICY_RE = re.compile(r"block|spam|policy|denied|reput|rbl|blacklist|blocklist|not permitted|relay|authenticat|ip address", re.I)
ENHANCED_POLICY_RE = re.compile(r"\b5\.7\.\d+")

TYPO_DOMAINS = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gamil.com": "gmail.com",
    "gmail.con": "gmail.com", "gmail.co": "gmail.com", "hotmial.com": "hotmail.com",
    "hotmal.com": "hotmail.com", "yahooo.com": "yahoo.com", "yaho.com": "yahoo.com",
    "outlok.com": "outlook.com", "outllook.com": "outlook.com",
}

HELO_HOST = os.environ.get("HELO_HOST") or socket.getfqdn()
PROBE_HOST = "gmail-smtp-in.l.google.com"  # used only to test whether port 25 is reachable
_port25 = {"ok": None, "at": 0.0}


def parse_list(text):
    """Split pasted text into unique addresses, keeping first-seen order."""
    seen, out = set(), []
    for tok in SPLIT_RE.split(text or ""):
        tok = tok.strip("<>\"'()[]")
        if tok and tok.lower() not in seen:
            seen.add(tok.lower())
            out.append(tok)
    return out


def check_syntax(addr):
    """Return an error string, or None if the address is syntactically valid."""
    if addr.count("@") != 1:
        return "Must contain exactly one @"
    local, domain = addr.split("@")
    if not local or not domain:
        return "Missing the part before or after @"
    if len(addr) > 254 or len(local) > 64:
        return "Address is too long"
    if not LOCAL_RE.match(local):
        return "Part before @ has invalid characters or dots"
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(l) for l in labels):
        return "Domain name is not valid"
    if not re.fullmatch(r"[A-Za-z]{2,}|xn--[A-Za-z0-9-]+", labels[-1]):
        return "Domain ending is not valid"
    return None


@lru_cache(maxsize=4096)
def lookup_mx(domain):
    """Return (state, hosts). state: ok | nxdomain | null | nomx | error."""
    r = dns.resolver.Resolver()
    r.lifetime = 5
    try:
        ans = r.resolve(domain, "MX")
        recs = sorted((a.preference, str(a.exchange).rstrip(".")) for a in ans)
        if len(recs) == 1 and recs[0][1] == "":
            return "null", ()
        return "ok", tuple(h for _, h in recs)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", ()
    except dns.resolver.NoAnswer:
        pass  # RFC 5321: fall back to the domain's A/AAAA record
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return "error", ()
    for rtype in ("A", "AAAA"):
        try:
            r.resolve(domain, rtype)
            return "ok", (domain,)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return "error", ()
    return "nomx", ()


def smtp_available():
    """True if this host can open outbound connections on port 25 (cached 10 min)."""
    if os.environ.get("SMTP_PROBE", "auto").lower() == "off":
        return False
    if _port25["ok"] is None or time.time() - _port25["at"] > 600:
        try:
            socket.create_connection((PROBE_HOST, 25), timeout=5).close()
            _port25["ok"] = True
        except OSError:
            _port25["ok"] = False
        _port25["at"] = time.time()
    return _port25["ok"]


def classify_rcpt(code, msg=""):
    """Map an SMTP RCPT reply to accepted | rejected | unclear."""
    if code in (250, 251):
        return "accepted"
    if code in (550, 551, 553) and not ENHANCED_POLICY_RE.search(msg) and not POLICY_RE.search(msg):
        return "rejected"
    return "unclear"  # 4xx (greylisting), 552 (full), policy blocks, etc.


def _rcpt_session(host, addrs):
    """One connection, several RCPT probes. Returns [(code, msg)] aligned to addrs.
    Never issues DATA, so nothing is delivered."""
    results = []
    s = smtplib.SMTP(timeout=10, local_hostname=HELO_HOST)
    try:
        s.connect(host, 25)
        s.ehlo_or_helo_if_needed()
        for a in addrs:
            try:
                code, _ = s.docmd("MAIL FROM:<>")
                if code >= 400:
                    results.append((code, "sender refused"))
                    continue
                code, msg = s.docmd(f"RCPT TO:<{a}>")
                results.append((code, msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)))
                s.docmd("RSET")
            except (smtplib.SMTPException, OSError):
                break
    finally:
        try:
            s.close()
        except Exception:
            pass
    return results + [(0, "connection lost")] * (len(addrs) - len(results))


def _check_domain_group(domain, addrs, smtp):
    """Check all valid-syntax addresses sharing one domain. Returns {addr: result}."""
    def res(status, reason, checks):
        return {"status": status, "reason": reason, "checks": checks}

    base = ["syntax"]
    if domain.lower() in TYPO_DOMAINS:
        msg = f"Likely typo; did you mean {TYPO_DOMAINS[domain.lower()]}?"
        return {a: res(BOUNCE, msg, base) for a in addrs}

    state, hosts = lookup_mx(domain.lower())
    dns_checks = base + ["dns"]
    if state != "ok":
        status, reason = {
            "nxdomain": (BOUNCE, "Domain does not exist"),
            "null": (BOUNCE, "Domain declares it accepts no email"),
            "nomx": (BOUNCE, "Domain has no mail server"),
            "error": (UNKNOWN, "DNS lookup timed out; try again"),
        }[state]
        return {a: res(status, reason, dns_checks if state != "error" else base) for a in addrs}

    if not smtp:
        return {a: res(UNKNOWN, "Domain can receive email, but the mailbox was not checked "
                                "(SMTP checks are unavailable on this server)", dns_checks) for a in addrs}

    canary = "".join(random.choices(string.ascii_lowercase, k=14)) + "@" + domain
    replies = None
    for host in hosts[:3]:
        try:
            replies = _rcpt_session(host, [canary] + addrs)
            if replies[0][0] != 0:
                break
        except (OSError, smtplib.SMTPException):
            replies = None
    if not replies or replies[0][0] == 0:
        return {a: res(UNKNOWN, "Could not connect to the domain's mail server", dns_checks) for a in addrs}

    catch_all = classify_rcpt(*replies[0]) == "accepted"
    out = {}
    for a, (code, msg) in zip(addrs, replies[1:]):
        kind = classify_rcpt(code, msg)
        checks = dns_checks + ["smtp"]
        if kind == "accepted" and catch_all:
            out[a] = res(UNKNOWN, "Server accepts every address, so this one can't be confirmed", checks)
        elif kind == "accepted":
            out[a] = res(DELIVERABLE, "Mail server confirmed the mailbox exists", checks)
        elif kind == "rejected":
            out[a] = res(BOUNCE, f"Mail server says the mailbox does not exist ({code})", checks)
        elif code == 0:
            out[a] = res(UNKNOWN, "Connection to the mail server dropped", dns_checks)
        elif 400 <= code < 500:
            out[a] = res(UNKNOWN, f"Server deferred the check ({code}); possibly greylisting", checks)
        else:
            out[a] = res(UNKNOWN, f"Server refused to say ({code})", checks)
    return out


def check_many(addrs, smtp=None):
    """Check addresses; return a list of results in input order."""
    smtp = smtp_available() if smtp is None else smtp
    results, groups = {}, {}
    for a in addrs:
        err = check_syntax(a)
        if err:
            results[a] = {"status": BOUNCE, "reason": err, "checks": []}
        else:
            groups.setdefault(a.split("@")[1], []).append(a)
    # One task per domain: at most one connection per mail server at a time.
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_check_domain_group, d, g, smtp) for d, g in groups.items()]
        for f in futures:
            results.update(f.result())
    return [{"email": a, **results[a]} for a in addrs]
