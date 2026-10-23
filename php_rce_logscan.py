#!/usr/bin/env python3
"""
php_rce_logscan.py - Hunt for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and
Nextcloud Collabora CODE (CVE-2026-110447) activity in Apache access and error logs.

Read-only. Standard library only (Python 3.8+). Payloads found in URLs are
decoded as TEXT for reporting and are never executed.

Usage examples
  python3 php_rce_logscan.py /var/log/apache2/
  python3 php_rce_logscan.py access.log* error.log* other_vhosts_access.log*
  python3 php_rce_logscan.py /var/log/apache2/ --since 2026-10-20 --until "2026-10-21 19:57"
  python3 php_rce_logscan.py logs/ --json report.json --ioc-ip extra_ips.txt

Exit codes: 0 = no indicators, 1 = suspicious activity, 2 = likely compromise,
            3 = usage / input error.

What Apache logs can and cannot show
  * PHP2Shell runs in PHP's request start-up, before application code, and the
    trigger lives in the multipart POST body, which Apache does not log. The
    strongest log-side signals are worker crashes (error log), memory-exhaustion
    fatals, POST bursts and failed/empty POST responses. A quiet, crash-free
    success can't be ruled out from logs alone.
  * CVE-2026-110447 leaves clear traces: shell syntax in the request path,
    base64 payloads, and later requests to dropped web shells.

All timestamps are compared as server-local time. Error logs carry no time
zone; the time zone in access logs is dropped, so both sets of logs must come
from the same server (or the same time zone).
"""

import argparse
import base64
import binascii
import bisect
import bz2
import collections
import datetime as dt
import functools
import glob
import gzip
import json
import lzma
import os
import re
import sys
import urllib.parse

VERSION = "1.2 (2026-10-23)"

# ---------------------------------------------------------------- IOC data ---

# Published attacker infrastructure (CVE-2026-110447, Sep/Oct 2026 reports)
# plus sources seen spraying the same payload family in a 2026-10 engagement.
KNOWN_BAD_IPS = {
    "139.28.18.122": "CVE-2026-110447 attacks 10-11 Sep 2026 (public reporting)",
    "89.38.98.50": "CVE-2026-110447 attempt 14 Sep 2026 (public reporting)",
    "43.133.147.108": "Nx_*.php web-shell dropper spray, 15 Oct 2026 (observed)",
    "27.121.112.182": "Nx_*.php web-shell dropper spray, 16 Oct 2026 (observed)",
    "103.3.221.233": "probe for Noname*_.php web shell, 16 Oct 2026 (observed)",
}

KNOWN_BAD_DOMAINS = ["webhook.site"]

# Web-shell file names reported for CVE-2026-110447 campaigns.
#   shx13a86.php, shxa35d0.php, shrf4645.php ...   (public reporting)
#   Nx_34486.php, Nx_44366.php                     (decoded dropper payloads)
#   Noname9619_.php                                (probe for an earlier drop)
WEBSHELL_NAME_RE = re.compile(
    r"/(?:sh[xr]f?[0-9a-z]{3,8}|nx_\d{3,8}|noname\d{2,8}_)\.php\b", re.I)

# Shell syntax inside a URL (checked after URL-decoding).
CMDI_RE = re.compile(
    r"(\$\(|\$\{ifs\}|`[^`]{1,200}`|base64\s*-d|\|\s*(?:ba)?sh\b|;\s*(?:ba)?sh\b"
    r"|/bin/(?:ba)?sh\b|\b(?:wget|curl)\s+-|\bchmod\s+\+?[0-7x])", re.I)

TRAVERSAL_RE = re.compile(r"(\.\./|\.\.%2f|%2e%2e|\.%2e/)", re.I)

# A web-shell style parameter whose VALUE looks like a command. The value test
# matters: Nextcloud previews legitimately use c= (etag) and x=/y=.
SHELL_PARAM_RE = re.compile(r"(?:^|[?&])(c|cmd|command|exec|execute|e|x|q|run)=([^&]*)", re.I)
SHELL_VALUE_RE = re.compile(
    r"^\s*(id|whoami|uname(\s.*)?|hostname|pwd|ls(\s.*)?|cat\s.+|echo\s.+|wget\s.+|"
    r"curl\s.+|bash.*|sh\s.+|python[0-9.]*\s.+|perl\s.+|nc\s.+|ncat\s.+|chmod\s.+|"
    r"find\s.+|ps(\s.*)?|netstat.*|ss\s.+|ifconfig.*|ip\s+a.*|base64\s.+|rm\s.+|"
    r"cd\s.+|sudo\s.+|crontab.*|php\s.+)\s*$", re.I)

# Front controllers / endpoints that answer 2xx regardless of the query string,
# so "?c=id -> 200" on them is a probe, not a working web shell.
KNOWN_ENTRYPOINTS = ("/index.php", "/status.php", "/remote.php", "/public.php", "/cron.php",
                     "/ocs/v1.php", "/ocs/v2.php", "/ocs-provider/index.php",
                     "/ocm-provider/index.php", "/wp-login.php", "/xmlrpc.php",
                     "/wp-admin/admin-ajax.php", "/wp-cron.php")

# User-Agent strings hard-wired by public PHP2Shell PoC/exploit tools. A hit is
# a strong lead, but attackers change the UA freely, so a MISS proves nothing.
TOOL_UA_RE = re.compile(r"php2shell[-/]10961[89]|php2shell[-/](?:poc|exploit)?|CVE-2026-10961[89]", re.I)
# PHP_SESSION_UPLOAD_PROGRESS is the PHP2Shell trigger field. It belongs in a
# multipart POST *body* (which Apache does not log); seeing it in the request
# line / query string is anomalous.
UPLOAD_PROGRESS_RE = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I)

B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
PHP_IN_TEXT_RE = re.compile(r"<\?php|\b(?:system|shell_exec|passthru|exec|popen|proc_open|eval|assert)\s*\(", re.I)
DROPPED_FILE_RE = re.compile(r"(?:\bN=|>\s*\S*?/?)([\w.-]{2,60}\.php)\b")

# Error-log signals
CRASH_RE = re.compile(
    r"exit signal (?:segmentation fault|aborted|bus error|illegal instruction)|"
    r"\bAH00052\b|zend_mm_heap corrupted|double free|free\(\): invalid|"
    r"corrupted (?:size|double-linked)|malloc\(\)|stack smashing", re.I)
OOM_RE = re.compile(r"allowed memory size of \d+ bytes exhausted|\bout of memory\b", re.I)
# A PHP *Fatal error* ending "in Unknown on line 0" fired outside any script —
# allocation during request start-up, where PHP2Shell (CVE-2026-109618) triggers.
# Must be a Fatal error: ordinary "PHP Warning: PHP Startup: ... in Unknown on
# line 0" module-load messages are benign and must not match.
UNKNOWN0_RE = re.compile(r"PHP (?:Fatal error|Parse error).*in Unknown on line 0\b", re.I)
CMD_OUTPUT_RE = re.compile(
    r"(?:^|\s)(?:/bin/)?(?:ba)?sh: (?:\d+: )?|: command not found|base64: invalid input|"
    r"cannot create .*: permission denied", re.I)

# ------------------------------------------------------------- log parsing ---

ACCESS_RE = re.compile(
    r'^(?:(?P<vhost>[^\s:]+:\d+)\s+)?'
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
    r'(?: (?P<bytes_in>\d+|-) (?P<bytes_out>\d+|-))?')  # optional %I %O (combinedio)

ERROR_TIME_RE = re.compile(r"^\[(?:\w{3} )?(\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]")
ERROR_CLIENT_RE = re.compile(r"\[client ([^\]]+?)(?::\d+)?\]")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def open_log(path):
    with open(path, "rb") as fh:
        magic = fh.read(6)
    if magic[:2] == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if magic[:3] == b"BZh":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if magic == b"\xfd7zXZ\x00":
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


@functools.lru_cache(maxsize=65536)
def parse_access_time(s):
    # "21/Oct/2026:00:00:16 +0200" -> naive server-local datetime
    try:
        return dt.datetime(int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]),
                           int(s[12:14]), int(s[15:17]), int(s[18:20]))
    except (ValueError, KeyError, IndexError):
        return None


def parse_error_time(line):
    m = ERROR_TIME_RE.match(line)
    if not m:
        return None
    mon, day, hh, mm, ss, year = m.groups()
    try:
        return dt.datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except (KeyError, ValueError):
        return None


def full_decode(s, rounds=3):
    for _ in range(rounds):
        new = urllib.parse.unquote(s)
        if new == s:
            break
        s = new
    return s


def sniff_type(path):
    name = os.path.basename(path).lower()
    if "error" in name:
        return "error"
    if "access" in name:
        return "access"
    try:
        with open_log(path) as fh:
            for i, line in enumerate(fh):
                if ERROR_TIME_RE.match(line):
                    return "error"
                if ACCESS_RE.match(line):
                    return "access"
                if i > 50:
                    break
    except OSError:
        pass
    return None


def expand_inputs(items):
    files = []
    for item in items:
        matches = glob.glob(item) or [item]
        for m in matches:
            if os.path.isdir(m):
                for root, _, names in os.walk(m):
                    for n in sorted(names):
                        files.append(os.path.join(root, n))
            elif os.path.isfile(m):
                files.append(m)
            else:
                print(f"warning: not found: {m}", file=sys.stderr)
    return sorted(set(files))


def try_b64_decode(blob):
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable / len(text) > 0.9 else None


def looks_b64(blob):
    """Cheap filter so ordinary URL paths (a/b/c/123) aren't decoded."""
    if blob.count("/") * 12 > len(blob):
        return False
    return (any(c.isupper() for c in blob) and any(c.islower() for c in blob)
            and any(c.isdigit() for c in blob))


def decode_payloads(text, depth=0, out=None):
    """Recursively base64-decode blobs found in text. Text only, never executed."""
    if out is None:
        out = []
    if depth > 3:
        return out
    for blob in B64_RUN_RE.findall(text):
        if not looks_b64(blob):
            continue
        dec = try_b64_decode(blob)
        if dec and dec not in out:
            out.append(dec)
            decode_payloads(dec, depth + 1, out)
    return out


# ---------------------------------------------------------------- findings ---

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Findings:
    def __init__(self, max_examples=3):
        self.items = {}
        self.max_examples = max_examples

    def add(self, sev, rule, key, title, when=None, example=None, detail=None):
        k = (rule, key)
        f = self.items.get(k)
        if f is None:
            f = self.items[k] = {"severity": sev, "rule": rule, "key": key, "title": title,
                                 "count": 0, "first": None, "last": None,
                                 "examples": [], "details": []}
        if SEVERITIES.index(sev) < SEVERITIES.index(f["severity"]):
            f["severity"] = sev
        f["count"] += 1
        if when:
            f["first"] = when if f["first"] is None or when < f["first"] else f["first"]
            f["last"] = when if f["last"] is None or when > f["last"] else f["last"]
        if example and len(f["examples"]) < self.max_examples and example not in f["examples"]:
            f["examples"].append(example)
        if detail and detail not in f["details"] and len(f["details"]) < 10:
            f["details"].append(detail)

    def sorted(self):
        return sorted(self.items.values(),
                      key=lambda f: (SEVERITIES.index(f["severity"]), f["first"] or dt.datetime.min))


CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def short(s, n=220):
    s = CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group()), s)
    return s if len(s) <= n else s[:n] + "..."


# ----------------------------------------------------------------- scanner ---

class Scanner:
    def __init__(self, args):
        self.args = args
        self.since = args.since
        self.until = args.until
        self.f = Findings(args.examples)
        self.bad_ips = dict(KNOWN_BAD_IPS)
        self.dropped_names = set()          # filled from decoded payloads
        self.crash_times = []               # error-log crash timestamps
        self.crash_ctx = collections.defaultdict(list)
        self.stats = collections.Counter()
        self.coverage = {}                  # file -> (first, last, lines, type)
        self.scripts_before = set()
        self.scripts_window = collections.defaultdict(lambda: [0, None, None, set()])
        self.post_per_min = collections.Counter()
        self.post_times = collections.defaultdict(list)   # ip -> [POST datetimes] for slow-burst
        self.ip_methods = collections.defaultdict(collections.Counter)
        self.richdoc_status = collections.Counter()
        self.saw_bytes_in = False           # whether any line carried %I

    def is_legit_script(self, sp):
        if not sp:
            return False
        lsp = sp.lower()
        return lsp.endswith(KNOWN_ENTRYPOINTS) or sp in self.scripts_before

    def in_window(self, t):
        if t is None:
            return True
        if self.since and t < self.since:
            return False
        if self.until and t > self.until:
            return False
        return True

    # ---- error logs -------------------------------------------------------
    def scan_error(self, path):
        first = last = None
        n = 0
        with open_log(path) as fh:
            for line in fh:
                n += 1
                t = parse_error_time(line)
                if t:
                    first = t if first is None or t < first else first
                    last = t if last is None or t > last else last
                if not self.in_window(t):
                    continue
                cm = ERROR_CLIENT_RE.search(line)
                client = cm.group(1) if cm else "-"
                text = line.strip()
                if CRASH_RE.search(line):
                    self.stats["crashes"] += 1
                    if t:
                        self.crash_times.append(t)
                    self.f.add("HIGH", "ERR-CRASH", "worker-crash",
                               "Apache/PHP worker crash (memory corruption; main PHP2Shell signal)",
                               t, short(text))
                elif UNKNOWN0_RE.search(line):
                    self.f.add("HIGH", "ERR-UNKNOWN0", client,
                               "PHP fatal 'in Unknown on line 0' (allocation failed during request "
                               "start-up, not in any script; strong PHP2Shell CVE-2026-109618 signal)",
                               t, short(text))
                elif OOM_RE.search(line):
                    self.f.add("MEDIUM", "ERR-OOM", client,
                               "PHP memory exhaustion fatal (PHP2Shell CVE-2026-109618 trigger condition; also normal app OOM)",
                               t, short(text))
                if CMD_OUTPUT_RE.search(line):
                    self.f.add("HIGH", "ERR-CMDOUT", client,
                               "Shell/command output in error log (command injection executed?)",
                               t, short(text))
                if "richdocumentscode" in line:
                    self.f.add("INFO", "ERR-RICHDOC", client,
                               "Error mentioning Collabora CODE app (richdocumentscode)", t, short(text))
                for dom in KNOWN_BAD_DOMAINS:
                    if dom in line.lower():
                        self.f.add("HIGH", "ERR-BADDOMAIN", dom, f"Known callback domain {dom} in error log",
                                   t, short(text))
        self.coverage[path] = (first, last, n, "error")

    # ---- access logs, pass 1: collect payload-derived IOCs and baseline -----
    def prepass_access(self, path):
        with open_log(path) as fh:
            for line in fh:
                m = ACCESS_RE.match(line)
                if not m:
                    continue
                t = parse_access_time(m.group("time"))
                method, uri = split_request(m.group("req"))
                if B64_RUN_RE.search(uri):
                    for dec in decode_payloads(uri):
                        for name in DROPPED_FILE_RE.findall(dec):
                            self.dropped_names.add(name.lower())
                if self.since and t and t < self.since and m.group("status").startswith("2"):
                    sp = script_path(uri)
                    if sp:
                        self.scripts_before.add(sp)

    # ---- access logs, pass 2: rules -----------------------------------------
    def scan_access(self, path):
        first = last = None
        n = 0
        self.crash_times.sort()
        win = dt.timedelta(seconds=self.args.crash_window)
        with open_log(path) as fh:
            for line in fh:
                n += 1
                m = ACCESS_RE.match(line)
                if not m:
                    self.stats["unparsed_access_lines"] += 1
                    continue
                t = parse_access_time(m.group("time"))
                if t:
                    first = t if first is None or t < first else first
                    last = t if last is None or t > last else last
                if not self.in_window(t):
                    continue
                self.stats["requests"] += 1
                ip = m.group("ip")
                status = m.group("status")
                size = m.group("size")
                ua = m.group("ua") or ""
                ref = m.group("ref") or ""
                raw_req = m.group("req")
                method, uri = split_request(raw_req)
                req = uri
                low = uri.lower()
                ok = status.startswith("2")
                tstr = fmt_t(t)
                ex = f"{tstr} {ip} {method} {short(uri, 160)} -> {status} {size}"

                self.ip_methods[ip][method] += 1

                # crash correlation
                if t and self.crash_times:
                    i = bisect.bisect_left(self.crash_times, t - win)
                    while i < len(self.crash_times) and self.crash_times[i] <= t + win:
                        ctx = self.crash_ctx[self.crash_times[i]]
                        if len(ctx) < 40:
                            ctx.append(ex)
                        i += 1

                # known bad IPs / domains
                if ip in self.bad_ips:
                    hit = ok and not (method in ("GET", "HEAD") and self.is_legit_script(script_path(uri)))
                    self.f.add("HIGH" if hit else "MEDIUM", "IOC-IP", ip,
                               f"Known malicious IP ({self.bad_ips[ip]})", t, ex)
                for dom in KNOWN_BAD_DOMAINS:
                    if dom in req.lower() or dom in ref.lower():
                        self.f.add("HIGH", "IOC-DOMAIN", ip, f"Known callback domain {dom} in request",
                                   t, ex)

                # exploit-tool User-Agent: near-zero false positives (nothing
                # legitimate sends it), so a hit is a strong, targeted-attempt
                # signal -> HIGH. Low recall (attackers change the UA) is a
                # caveat in the text, not a reason to downrate the hit.
                if TOOL_UA_RE.search(ua):
                    self.f.add("HIGH", "UA-TOOL", ip,
                               "User-Agent matches a known PHP2Shell PoC/exploit tool - a targeted "
                               "exploitation attempt (near-zero false positives; note the converse does "
                               "not hold: a real attacker changes the UA, so absence proves nothing)",
                               t, ex, f"UA: {short(ua, 90)}")
                # PHP2Shell trigger field in the URL (normally a POST body field)
                if UPLOAD_PROGRESS_RE.search(uri):
                    self.f.add("MEDIUM", "UPLOAD-PROGRESS-URI", ip,
                               "PHP_SESSION_UPLOAD_PROGRESS in the request line (PHP2Shell trigger field; "
                               "normally carried in the POST body, so anomalous in a URL)", t, ex)

                # --- CVE-2026-110447 (Collabora CODE / richdocumentscode) ---
                if "/apps/richdocumentscode/" in low:
                    self.richdoc_status[status] += 1
                    is_proxy = "/proxy.php" in low
                    if is_proxy and (CMDI_RE.search(uri) or TRAVERSAL_RE.search(raw_req)):
                        self.f.add("HIGH" if ok else "MEDIUM", "CODE-INJECT", ip,
                                   "CVE-2026-110447 injection attempt against richdocumentscode/proxy.php"
                                   + (" (script answered 2xx - check host!)" if ok else ""), t, ex)
                    elif not is_proxy and ".php" in low:
                        self.f.add("CRITICAL" if ok else "LOW", "CODE-EXTRAPHP", ip,
                                   "Non-standard PHP file requested in richdocumentscode app dir"
                                   + (" and SERVED (web shell?)" if ok else " (probe, not found)"), t, ex)

                # dropped web-shell names (published + decoded from payloads)
                base = low.split("?")[0]
                name_hit = WEBSHELL_NAME_RE.search(base)
                dyn_hit = any(base.endswith("/" + d) for d in self.dropped_names)
                if name_hit or dyn_hit:
                    self.f.add("CRITICAL" if ok else "LOW", "WEBSHELL-NAME", ip,
                               "Request for known/decoded web-shell filename"
                               + (" - SERVED, shell exists and was used" if ok else " (not found)"), t, ex)

                # web-shell command parameter
                q = uri.split("?", 1)[1] if "?" in uri else ""
                sp_here = script_path(uri)
                legit = self.is_legit_script(sp_here)
                for pname, pval in SHELL_PARAM_RE.findall(q):
                    v = urllib.parse.unquote_plus(pval)
                    if SHELL_VALUE_RE.match(v) and ".php" in low:
                        if ok and not legit:
                            sev, note = "CRITICAL", " and answered 2xx"
                        elif ok:
                            sev, note = "MEDIUM", " (2xx from a legitimate endpoint that ignores the parameter - probe)"
                        else:
                            sev, note = "MEDIUM", ""
                        self.f.add(sev, "WEBSHELL-CMD", ip, f"Command passed via '{pname}=' to a PHP file" + note,
                                   t, ex, f"{pname}={short(v, 80)}")

                # generic command injection in the URL (spray)
                if "/apps/richdocumentscode/" not in low and CMDI_RE.search(uri):
                    if ok and sp_here and not legit:
                        sev, note = "HIGH", " - answered 2xx by a non-standard script, review"
                    elif ok:
                        sev, note = "LOW", " - 2xx from default page/front controller (not proof of execution)"
                    else:
                        sev, note = "LOW", ""
                    self.f.add(sev, "URL-CMDI", ip, "Shell syntax in request URL (exploit spray)" + note, t, ex)

                # decode base64 payloads (text only)
                if B64_RUN_RE.search(req):
                    for dec in decode_payloads(req):
                        if PHP_IN_TEXT_RE.search(dec) or CMDI_RE.search(dec) or "base64" in dec:
                            names = sorted(set(DROPPED_FILE_RE.findall(dec)))
                            self.f.add("HIGH" if ok else "MEDIUM", "PAYLOAD", ip,
                                       "Base64 payload in URL decodes to shell/PHP code",
                                       t, ex, short(dec, 300) + (f"  [drops: {', '.join(names)}]" if names else ""))

                # --- PHP2Shell heuristics ---
                if method == "POST":
                    self.stats["posts"] += 1
                    if t:
                        self.post_per_min[(ip, tstr[:16])] += 1
                        self.post_times[ip].append(t)
                    if status.startswith("5") or size in ("-", "0") or status == "-":
                        self.f.add("LOW", "POST-FAIL", ip,
                                   "POST with 5xx or empty response (possible worker crash / OOM)", t, ex)
                    # oversized request body to a PHP endpoint (needs %I in log format)
                    bin_ = m.group("bytes_in")
                    if bin_ and bin_ != "-":
                        self.saw_bytes_in = True
                        if int(bin_) >= self.args.oversized and ".php" in low:
                            self.f.add("MEDIUM", "BIG-POST", ip,
                                       f"Large POST body (>= {self.args.oversized} bytes) to a PHP endpoint "
                                       "(PHP2Shell heap-spray / brute-force footprint)",
                                       t, ex, f"{bin_} bytes in")

                # first-seen PHP scripts in window (needs --since baseline)
                if ok:
                    sp = script_path(uri)
                    if sp:
                        rec = self.scripts_window[sp]
                        rec[0] += 1
                        rec[1] = t if rec[1] is None or (t and t < rec[1]) else rec[1]
                        rec[2] = ex if rec[2] is None else rec[2]
                        rec[3].add(ip)
        self.coverage[path] = (first, last, n, "access")

    def finish(self):
        for (ip, minute), cnt in self.post_per_min.items():
            if cnt >= self.args.burst:
                self.f.add("MEDIUM", "POST-BURST", ip,
                           f"POST burst >= {self.args.burst}/min from one IP (offset probing / spraying?)",
                           dt.datetime.strptime(minute, "%Y-%m-%d %H:%M"), f"{minute} {ip}: {cnt} POSTs")
        # slow burst: many POSTs from one IP inside a sliding window (minutes).
        # The noisy PHP2Shell variant is ~590 oversized POSTs over ~15 min, which
        # the per-minute rule above can miss if the attacker paces the requests.
        span = dt.timedelta(minutes=self.args.slow_burst_min)
        for ip, times in self.post_times.items():
            times.sort()
            best, lo = 0, 0
            for hi in range(len(times)):
                while times[hi] - times[lo] > span:
                    lo += 1
                best = max(best, hi - lo + 1)
            if best >= self.args.slow_burst:
                self.f.add("MEDIUM", "POST-SLOWBURST", ip,
                           f"POST burst >= {self.args.slow_burst} within {self.args.slow_burst_min} min "
                           "from one IP (paced heap-spray / brute-force?)",
                           times[0], f"{ip}: peak {best} POSTs in a {self.args.slow_burst_min}-min window "
                           f"({len(times)} total)")
        for ip, methods in self.ip_methods.items():
            total = sum(methods.values())
            if total >= 3 and methods.get("POST", 0) == total:
                self.f.add("LOW", "POST-ONLY", ip,
                           "Client sent only POST requests (no page loads; tool-like)",
                           None, f"{ip}: {total} POSTs, no other methods")
        if self.since and self.scripts_before:
            for sp, (cnt, first, ex, ips) in self.scripts_window.items():
                if sp not in self.scripts_before:
                    self.f.add("MEDIUM", "NEW-PHP", sp,
                               "PHP script answered 2xx in window but never before (new file? web shell?)",
                               first, ex, f"{cnt} hits from {len(ips)} IP(s): {', '.join(sorted(ips)[:5])}")
        for ct, ctx in sorted(self.crash_ctx.items()):
            for line in ctx[: self.args.examples * 3]:
                self.f.add("INFO", "CRASH-CTX", ct.strftime("%Y-%m-%d %H:%M:%S"),
                           f"Requests within {self.args.crash_window}s of a worker crash", ct, None, line)
        if self.richdoc_status:
            served = sum(v for k, v in self.richdoc_status.items() if k.startswith("2"))
            self.f.add("INFO", "CODE-PRESENT", "richdocumentscode",
                       "Collabora CODE app paths requested; status codes: "
                       + ", ".join(f"{k}x{v}" for k, v in sorted(self.richdoc_status.items()))
                       + ("  -> app reachable, verify version >= 26.4.303" if served else
                          "  -> never served (app likely not installed)"))

    def verdict(self):
        sevs = {f["severity"] for f in self.f.items.values()}
        if "CRITICAL" in sevs:
            return 2, "LIKELY COMPROMISE - indicators of successful exploitation / web-shell use"
        if "HIGH" in sevs or "MEDIUM" in sevs:
            return 1, "SUSPICIOUS - attack activity or anomalies found, manual review needed"
        return 0, "NO INDICATORS in the supplied logs (does not prove the host is clean)"


def split_request(raw):
    """Split the raw request line first, then URL-decode the URI, so encoded
    spaces (%20) inside the URI don't cut it short."""
    parts = raw.split(" ")
    if len(parts) >= 3:
        method, uri = parts[0], " ".join(parts[1:-1])
    elif len(parts) == 2:
        method, uri = parts
    else:
        method, uri = "-", raw
    return method, full_decode(uri)


def script_path(uri):
    p = uri.split("?", 1)[0]
    i = p.lower().find(".php")
    if i < 0:
        return None
    return p[: i + 4]


# ------------------------------------------------------------------ output ---

def fmt_t(t):
    return (f"{t.year:04}-{t.month:02}-{t.day:02} {t.hour:02}:{t.minute:02}:{t.second:02}"
            if t else "-")


def print_report(sc, code, verdict):
    a = sc.args
    print(f"php_rce_logscan {VERSION}")
    print("=" * 78)
    win = f"{fmt_t(sc.since) if sc.since else 'start'} .. {fmt_t(sc.until) if sc.until else 'end'}"
    print(f"Window: {win}   (server-local time)")
    print("\nLog coverage:")
    for p, (first, last, n, typ) in sorted(sc.coverage.items()):
        print(f"  [{typ:6}] {p}: {n} lines, {fmt_t(first)} .. {fmt_t(last)}")
    print(f"\nRequests in window: {sc.stats['requests']}  POSTs: {sc.stats['posts']}  "
          f"Worker crashes: {sc.stats['crashes']}  Unparsed access lines: {sc.stats['unparsed_access_lines']}")
    if sc.dropped_names:
        print("Web-shell names decoded from payloads: " + ", ".join(sorted(sc.dropped_names)))
    if not any(t == "error" for *_, t in sc.coverage.values()):
        print("\n!! No error log supplied: worker crashes (main PHP2Shell signal) cannot be checked.")
    if a.since and not sc.scripts_before:
        print("\n!! No access-log data before --since: new-PHP-file baseline check skipped.")
    if not sc.saw_bytes_in:
        print("\n!! Log format has no %I (bytes received): oversized-POST detection (BIG-POST) "
              "is blind. Add %I to the Apache LogFormat to see PHP2Shell heap-spray bodies.")

    findings = sc.f.sorted()
    for sev in SEVERITIES:
        group = [f for f in findings if f["severity"] == sev]
        if not group or (sev == "INFO" and a.quiet):
            continue
        print(f"\n{'-' * 30} {sev} ({len(group)}) {'-' * (44 - len(sev))}")
        for f in group:
            span = f"{fmt_t(f['first'])} .. {fmt_t(f['last'])}" if f["first"] else ""
            print(f"[{f['rule']}] {f['title']}")
            print(f"    key: {f['key']}   count: {f['count']}   {span}")
            for d in f["details"]:
                print(f"    > {d}")
            for e in f["examples"]:
                print(f"    e.g. {e}")
    print("\n" + "=" * 78)
    print(f"VERDICT: {verdict}")
    print("Limits: Apache logs hold no POST bodies or cookies; a crash-free successful "
          "PHP2Shell exploit can't be excluded. Confirm on the host (processes, "
          "outbound connections, new .php files, `occ integrity:check-core`).")


def to_json(sc, code, verdict):
    def conv(o):
        if isinstance(o, dt.datetime):
            return o.isoformat()
        if isinstance(o, set):
            return sorted(o)
        raise TypeError
    return json.dumps({
        "version": VERSION, "verdict_code": code, "verdict": verdict,
        "since": sc.since, "until": sc.until,
        "coverage": {p: {"type": c[3], "lines": c[2], "first": c[0], "last": c[1]}
                     for p, c in sc.coverage.items()},
        "stats": dict(sc.stats), "decoded_webshell_names": sc.dropped_names,
        "findings": sc.f.sorted(),
    }, default=conv, indent=2)


def parse_when(s):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"bad time '{s}', use YYYY-MM-DD[ HH:MM[:SS]]")


def main():
    ap = argparse.ArgumentParser(description="Hunt PHP2Shell / CVE-2026-110447 indicators in Apache logs.")
    ap.add_argument("paths", nargs="+", help="log files, globs or directories (gz/bz2/xz ok)")
    ap.add_argument("--since", type=parse_when, help="window start, server-local (YYYY-MM-DD[ HH:MM])")
    ap.add_argument("--until", type=parse_when, help="window end, e.g. patch + restart time")
    ap.add_argument("--burst", type=int, default=30, help="POSTs/min/IP threshold (default 30)")
    ap.add_argument("--slow-burst", type=int, default=100,
                    help="POSTs/IP within the slow-burst window to flag (default 100)")
    ap.add_argument("--slow-burst-min", type=int, default=15,
                    help="slow-burst window length in minutes (default 15)")
    ap.add_argument("--oversized", type=int, default=500000,
                    help="request-body size (bytes) to flag as oversized POST; needs %%I in log (default 500000)")
    ap.add_argument("--crash-window", type=int, default=5, help="seconds around a crash to correlate (default 5)")
    ap.add_argument("--ioc-ip", help="file with extra bad IPs, one per line (# comments ok)")
    ap.add_argument("--examples", type=int, default=3, help="examples per finding (default 3)")
    ap.add_argument("--json", help="also write a JSON report to this file")
    ap.add_argument("-q", "--quiet", action="store_true", help="hide INFO findings")
    args = ap.parse_args()

    files = expand_inputs(args.paths)
    if not files:
        print("no input files", file=sys.stderr)
        return 3
    sc = Scanner(args)
    if args.ioc_ip:
        with open(args.ioc_ip) as fh:
            for line in fh:
                ip = line.split("#")[0].strip()
                if ip:
                    sc.bad_ips.setdefault(ip, "user-supplied IOC")

    typed = [(p, sniff_type(p)) for p in files]
    errors = [p for p, t in typed if t == "error"]
    access = [p for p, t in typed if t == "access"]
    for p, t in typed:
        if t is None:
            print(f"warning: skipped (not an Apache log?): {p}", file=sys.stderr)

    for p in errors:                 # crashes first, so access pass can correlate
        sc.scan_error(p)
    for p in access:
        sc.prepass_access(p)
    for p in access:
        sc.scan_access(p)
    sc.finish()

    code, verdict = sc.verdict()
    print_report(sc, code, verdict)
    if args.json:
        with open(args.json, "w") as fh:
            fh.write(to_json(sc, code, verdict))
    return code


if __name__ == "__main__":
    sys.exit(main())
