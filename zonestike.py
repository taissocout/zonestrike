#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneStrike v1.7.0 — Clean Auto Recon + TCP Port Scan + Rich Reports (JSON/CSV/HTML)
Use ONLY with explicit authorization.

Usage (AUTO):
  python3 zonestrike.py <TARGET> <TOP_N_PORTS> <REPORT_NAME>

Example:
  python3 zonestrike.py lab.local 100 lab_report
"""

import asyncio
import csv
import json
import os
import random
import re
import ssl
import sys
import webbrowser
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import dns.resolver

VERSION = "1.7.0"

CREDITS_NAME = "Cout"
CREDITS_LINKEDIN = "https://www.linkedin.com/in/SEU_LINKEDIN"
CREDITS_GITHUB = "https://github.com/taissocout/zonestrike"

BANNER = rf"""
███████╗ ██████╗ ███╗   ██╗███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
███████╗╚██████╔╝██║ ╚████║███████╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

ZoneStrike v{VERSION} — Clean Auto Recon + TCP Scan + Reporting
Use ONLY with explicit authorization.
Credits: {CREDITS_NAME} | LinkedIn: {CREDITS_LINKEDIN} | GitHub: {CREDITS_GITHUB}
"""

DEFAULT_NMAP_SERVICES_PATHS = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]

LIKELY_WEB_PORTS_PLAIN = {80, 8080, 8000, 8888, 3000, 10000}
LIKELY_WEB_PORTS_TLS = {443, 8443, 9443}

# Seeds curtas (conveniência, não brute agressivo)
EMBEDDED_SEEDS = ["www", "dev", "api", "mail", "intranet", "vpn", "portal", "admin", "staging", "test"]


# -------------------- Models --------------------
@dataclass
class DiscoveryHit:
    fqdn: str
    source: str
    evidence: str
    ips: List[str]

@dataclass
class PortFinding:
    port: int
    proto: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: Optional[str] = None
    evidence: Optional[str] = None
    banner: Optional[str] = None
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None

@dataclass
class HostReport:
    ip: str
    name: str
    open_ports: List[PortFinding]
    errors: List[str]

@dataclass
class ScanReport:
    target: str
    top_n_ports: int
    ports_count: int
    discovered_fqdns: int
    discovered_ips: int
    discovery: List[DiscoveryHit]
    hosts: List[HostReport]
    started_at: str
    finished_at: str
    version: str = VERSION


# -------------------- Utils --------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def uniq(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def safe_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)

def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))

def pick_default_wordlist() -> Optional[str]:
    for p in ("wordlists/basic.txt", "wordlists/common.txt", "wordlist.txt"):
        pp = Path(p)
        if pp.exists() and pp.is_file():
            return str(pp)
    return None


# -------------------- nmap-services --------------------
def find_nmap_services_file() -> Optional[str]:
    for p in DEFAULT_NMAP_SERVICES_PATHS:
        if Path(p).exists():
            return p
    return None

def load_nmap_services_map(path: str) -> Dict[int, str]:
    out: Dict[int, str] = {}
    rx = re.compile(r"^\s*([^\s]+)\s+(\d+)\/(tcp|udp)\s+([0-9.]+)")
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if not m:
            continue
        svc = m.group(1).strip()
        port = int(m.group(2))
        proto = m.group(3).strip()
        if proto == "tcp" and 1 <= port <= 65535 and port not in out:
            out[port] = svc
    return out

def top_ports_from_nmap_services(path: str, n: int) -> List[int]:
    rx = re.compile(r"^\s*([^\s]+)\s+(\d+)\/(tcp|udp)\s+([0-9.]+)")
    rows: List[Tuple[float, int]] = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if not m:
            continue
        port = int(m.group(2))
        proto = m.group(3).strip()
        freq = float(m.group(4))
        if proto == "tcp" and 1 <= port <= 65535:
            rows.append((freq, port))
    rows.sort(reverse=True, key=lambda x: x[0])
    out: List[int] = []
    seen: Set[int] = set()
    for _, p in rows:
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= n:
            break
    return out


# -------------------- DNS Discovery (clean + safe) --------------------
def resolve_ips(name: str, timeout: float = 3.0) -> List[str]:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    ips: List[str] = []
    try:
        ans = r.resolve(name, "A")
        ips.extend([rr.to_text() for rr in ans])
    except Exception:
        pass
    try:
        ans = r.resolve(name, "AAAA")
        ips.extend([rr.to_text() for rr in ans])
    except Exception:
        pass
    return uniq([ip for ip in ips if ip])

def passive_discovery(target: str, timeout: float = 3.0) -> List[Tuple[str, str, str]]:
    """
    Returns list of (fqdn, source, evidence).
    Lightweight queries: NS/MX/TXT + includes apex itself.
    """
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    out: List[Tuple[str, str, str]] = []
    out.append((target, "passive", "apex"))

    # NS
    try:
        ans = r.resolve(target, "NS")
        for rr in ans:
            out.append((rr.to_text().rstrip("."), "passive", "NS"))
    except Exception:
        pass

    # MX
    try:
        ans = r.resolve(target, "MX")
        for rr in ans:
            out.append((str(rr.exchange).rstrip("."), "passive", "MX"))
    except Exception:
        pass

    # TXT (extract fqdn tokens)
    try:
        ans = r.resolve(target, "TXT")
        for rr in ans:
            txt = " ".join([b.decode("utf-8", errors="ignore") for b in rr.strings])
            for m in re.findall(r"([a-zA-Z0-9._-]+\." + re.escape(target) + r")", txt):
                out.append((m, "passive", "TXT"))
    except Exception:
        pass

    return out

def seeds_discovery(target: str) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    for s in EMBEDDED_SEEDS:
        out.append((f"{s}.{target}", "seed", "embedded"))
    return out

def wordlist_discovery(target: str, wordlist_path: str, limit: int = 500) -> List[Tuple[str, str, str]]:
    """
    Uses user-provided file if exists.
    Each line: label (dev) or fqdn (dev.example.com).
    """
    p = Path(wordlist_path)
    if not p.exists():
        return []
    out: List[Tuple[str, str, str]] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        fqdn = s if "." in s else f"{s}.{target}"
        out.append((fqdn, "wordlist", f"file:{p.name}"))
        if limit and len(out) >= limit:
            break
    return out

def run_discovery(target: str, timeout: float = 3.0) -> Tuple[List[DiscoveryHit], Dict[str, str]]:
    """
    Returns:
      - discovery hits (fqdn/source/evidence/ips)
      - ip_to_best_name mapping
    """
    items: List[Tuple[str, str, str]] = []
    items.extend(passive_discovery(target, timeout=timeout))
    items.extend(seeds_discovery(target))

    wl = pick_default_wordlist()
    if wl:
        items.extend(wordlist_discovery(target, wl, limit=500))

    # Dedup by fqdn but keep multiple sources in evidence string
    by_fqdn: Dict[str, List[Tuple[str, str]]] = {}
    for fqdn, src, ev in items:
        by_fqdn.setdefault(fqdn, []).append((src, ev))

    hits: List[DiscoveryHit] = []
    ip_to_name: Dict[str, str] = {}

    for fqdn in sorted(by_fqdn.keys()):
        srcs = by_fqdn[fqdn]
        evidence = ";".join([f"{s}:{e}" for s, e in srcs])[:300]
        ips = resolve_ips(fqdn, timeout=timeout)
        if not ips:
            continue
        hits.append(DiscoveryHit(fqdn=fqdn, source="multi", evidence=evidence, ips=ips))
        for ip in ips:
            # first name wins (stable)
            ip_to_name.setdefault(ip, fqdn)

    # Fallback: if nothing resolves, try resolving the target apex
    if not hits:
        ips = resolve_ips(target, timeout=timeout)
        if ips:
            hits.append(DiscoveryHit(fqdn=target, source="fallback", evidence="no-discovery-resolved", ips=ips))
            for ip in ips:
                ip_to_name.setdefault(ip, target)

    return hits, ip_to_name


# -------------------- Scan (safe workers) --------------------
async def try_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_open_ports(ip: str, ports: List[int], concurrency: int, timeout: float) -> List[int]:
    q: asyncio.Queue[int] = asyncio.Queue()
    for p in ports:
        q.put_nowait(p)

    open_ports: List[int] = []
    lock = asyncio.Lock()
    concurrency = max(1, min(int(concurrency), 400))

    async def worker() -> None:
        while True:
            try:
                p = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if await try_connect(ip, p, timeout):
                    async with lock:
                        open_ports.append(p)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*workers)
    open_ports.sort()
    return open_ports


# -------------------- Enrich (banner + http probe) --------------------
def safe_decode(b: bytes, limit: int = 800) -> str:
    s = b.decode("utf-8", errors="replace")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s[:limit]

def infer_from_banner(banner: str) -> Dict[str, Optional[str]]:
    b = banner or ""
    m = re.search(r"^SSH-\d+\.\d+-([A-Za-z0-9._-]+)", b)
    if m:
        ident = m.group(1)
        m2 = re.search(r"(OpenSSH)[_-]([0-9A-Za-z.]+)", ident)
        if m2:
            return {"service": "ssh", "product": "OpenSSH", "version": m2.group(2), "confidence": "high", "evidence": "banner"}
        return {"service": "ssh", "product": ident, "version": None, "confidence": "high", "evidence": "banner"}

    if b.startswith("220 "):
        return {"service": "ftp", "product": None, "version": None, "confidence": "medium", "evidence": "banner"}
    if b.startswith("+OK"):
        return {"service": "pop3", "product": None, "version": None, "confidence": "medium", "evidence": "banner"}
    if b.startswith("* OK"):
        return {"service": "imap", "product": None, "version": None, "confidence": "medium", "evidence": "banner"}

    return {}

async def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(r.read(240), timeout=0.9)
            if data:
                return safe_decode(data)
        except Exception:
            return None
        finally:
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
        return None
    except Exception:
        return None

async def http_probe(ip: str, port: int, tls: bool, ua: str, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    try:
        ssl_ctx = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout)
        req = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: {ua}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        w.write(req)
        await w.drain()
        data = await asyncio.wait_for(r.read(2048), timeout=timeout)
        txt = data.decode("utf-8", errors="replace")

        status = None
        m = re.search(r"HTTP\/\d\.\d\s+(\d{3})", txt)
        if m:
            status = int(m.group(1))

        server = None
        m = re.search(r"(?im)^Server:\s*(.+)$", txt)
        if m:
            server = m.group(1).strip()

        title = None
        # quick GET for title (best effort)
        try:
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout)
            req2 = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: {ua}\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            w2.write(req2)
            await w2.drain()
            html = await asyncio.wait_for(r2.read(4096), timeout=timeout)
            htxt = html.decode("utf-8", errors="replace")
            mt = re.search(r"(?is)<title>\s*(.*?)\s*</title>", htxt)
            if mt:
                title = re.sub(r"\s+", " ", mt.group(1).strip())[:140]
            w2.close()
            try:
                await w2.wait_closed()
            except Exception:
                pass
        except Exception:
            pass

        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass

        return status, server, title
    except Exception:
        return None, None, None

async def enrich_ports(
    ip: str,
    open_ports: List[int],
    svc_map: Dict[int, str],
    banner_timeout: float = 1.8,
    http_timeout: float = 2.2,
    ua: str = "ZoneStrike/1.7.0 (authorized testing)",
) -> List[PortFinding]:
    findings: List[PortFinding] = []
    for p in open_ports:
        pf = PortFinding(port=p, proto="tcp", state="open")

        pf.banner = await grab_banner(ip, p, banner_timeout)
        if pf.banner:
            inf = infer_from_banner(pf.banner)
            if inf:
                pf.service = inf.get("service")
                pf.product = inf.get("product")
                pf.version = inf.get("version")
                pf.confidence = inf.get("confidence")
                pf.evidence = inf.get("evidence")

        if p in LIKELY_WEB_PORTS_PLAIN or p in LIKELY_WEB_PORTS_TLS:
            tls = p in LIKELY_WEB_PORTS_TLS
            st, sv, title = await http_probe(ip, p, tls, ua, http_timeout)
            pf.http_status = st
            pf.http_server = sv
            pf.http_title = title
            if (st is not None or sv or title) and not pf.service:
                pf.service = "https" if tls else "http"
                pf.confidence = pf.confidence or "medium"
                pf.evidence = pf.evidence or "http"
            if sv and not pf.product:
                pf.product = sv

        # fallback to nmap-services name
        if not pf.service:
            pf.service = svc_map.get(pf.port)
            if pf.service:
                pf.confidence = pf.confidence or "low"
                pf.evidence = pf.evidence or "nmap-services"

        findings.append(pf)

    findings.sort(key=lambda x: x.port)
    return findings


# -------------------- Reporting --------------------
def write_json(path: str, report: ScanReport) -> None:
    Path(path).write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")

def write_csv(path: str, report: ScanReport) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "ip", "port", "proto", "state", "service", "product", "version", "confidence", "evidence",
                    "banner", "http_status", "http_server", "http_title"])
        for hr in report.hosts:
            for pf in hr.open_ports:
                w.writerow([
                    hr.name, hr.ip,
                    pf.port, pf.proto, pf.state,
                    pf.service or "", pf.product or "", pf.version or "",
                    pf.confidence or "", pf.evidence or "",
                    pf.banner or "",
                    pf.http_status if pf.http_status is not None else "",
                    pf.http_server or "", pf.http_title or ""
                ])

def build_host_html(target: str, report_name: str, hr: HostReport) -> str:
    rows = []
    for pf in hr.open_ports:
        rows.append(
            "<tr>"
            f"<td class='mono'>{pf.port}</td>"
            f"<td>{html_escape(pf.service or '')}</td>"
            f"<td>{html_escape(pf.product or '')}</td>"
            f"<td>{html_escape(pf.version or '')}</td>"
            f"<td class='mono'>{html_escape(str(pf.http_status) if pf.http_status is not None else '')}</td>"
            f"<td>{html_escape(pf.http_server or '')}</td>"
            f"<td>{html_escape(pf.http_title or '')}</td>"
            f"<td><details><summary>banner</summary><pre>{html_escape(pf.banner or '')}</pre></details></td>"
            "</tr>"
        )
    if not rows:
        rows = ["<tr><td colspan='8'>No open ports found.</td></tr>"]

    return f"""<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZoneStrike — {html_escape(hr.name)} ({html_escape(hr.ip)})</title>
<style>
:root{{--bg:#0b0f17;--card:#111827;--muted:#9CA3AF;--text:#E5E7EB;--line:rgba(255,255,255,.08);--a:#60A5FA}}
body{{background:var(--bg);color:var(--text);font-family:system-ui,Arial;margin:24px}}
a{{color:var(--a)}} .mono{{font-family:ui-monospace,Menlo,Consolas,monospace}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin:12px 0}}
table{{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:14px;overflow:hidden}}
th,td{{border-bottom:1px solid var(--line);text-align:left;padding:10px;vertical-align:top}}
th{{background:rgba(255,255,255,.03);color:var(--muted);font-size:12px}}
pre{{white-space:pre-wrap;word-break:break-word;margin:8px 0 0 0}}
</style></head><body>
<h1>Host Report</h1>
<div class="card">
  <div><b>Target:</b> <span class="mono">{html_escape(target)}</span></div>
  <div><b>Host:</b> <span class="mono">{html_escape(hr.name)}</span></div>
  <div><b>IP:</b> <span class="mono">{html_escape(hr.ip)}</span></div>
  <div><b>Report:</b> <span class="mono">{html_escape(report_name)}</span></div>
</div>

<div class="card">
  <h2>Open Ports</h2>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>HTTP</th><th>Server</th><th>Title</th><th>Banner</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>

<div class="card">
  <div style="color:var(--muted);font-size:12px">
    Credits: {html_escape(CREDITS_NAME)} — <a href="{html_escape(CREDITS_LINKEDIN)}">LinkedIn</a> • <a href="{html_escape(CREDITS_GITHUB)}">GitHub</a>
  </div>
</div>
</body></html>"""

def build_index_html(report: ScanReport, html_files: List[Tuple[str, HostReport]]) -> str:
    # aggregated “service per host” summary
    rows = []
    for rel, hr in html_files:
        ports = ", ".join(f"{p.port}/{p.service or ''}" for p in hr.open_ports) if hr.open_ports else "None"
        rows.append(
            "<tr>"
            f"<td><a href='{html_escape(rel)}'>{html_escape(hr.name)}</a></td>"
            f"<td class='mono'>{html_escape(hr.ip)}</td>"
            f"<td class='mono'>{html_escape(ports)}</td>"
            f"<td class='mono'>{len(hr.open_ports)}</td>"
            "</tr>"
        )
    if not rows:
        rows = ["<tr><td colspan='4'>No hosts scanned.</td></tr>"]

    # discovery table
    drows = []
    for d in report.discovery:
        drows.append(
            "<tr>"
            f"<td class='mono'>{html_escape(d.fqdn)}</td>"
            f"<td class='mono'>{html_escape(', '.join(d.ips))}</td>"
            f"<td class='mono'>{html_escape(d.evidence)}</td>"
            "</tr>"
        )
    if not drows:
        drows = ["<tr><td colspan='3'>No discovery results.</td></tr>"]

    return f"""<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZoneStrike — Report Index — {html_escape(report.target)}</title>
<style>
:root{{--bg:#0b0f17;--card:#111827;--muted:#9CA3AF;--text:#E5E7EB;--line:rgba(255,255,255,.08);--a:#60A5FA}}
body{{background:var(--bg);color:var(--text);font-family:system-ui,Arial;margin:24px}}
a{{color:var(--a)}} .mono{{font-family:ui-monospace,Menlo,Consolas,monospace}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}}
.k{{color:var(--muted);font-size:12px}} .v{{font-size:22px;font-weight:700;margin-top:6px}}
table{{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:14px;overflow:hidden}}
th,td{{border-bottom:1px solid var(--line);text-align:left;padding:10px;vertical-align:top}}
th{{background:rgba(255,255,255,.03);color:var(--muted);font-size:12px}}
</style></head><body>
<h1>ZoneStrike — Report Index</h1>
<div style="color:var(--muted);font-size:12px">
Target: <span class="mono">{html_escape(report.target)}</span> | Version: <span class="mono">{html_escape(report.version)}</span>
</div>

<div class="grid">
  <div class="card"><div class="k">Top ports</div><div class="v">{report.top_n_ports}</div></div>
  <div class="card"><div class="k">Discovery (FQDNs)</div><div class="v">{report.discovered_fqdns}</div></div>
  <div class="card"><div class="k">Unique IPs</div><div class="v">{report.discovered_ips}</div></div>
  <div class="card"><div class="k">Hosts scanned</div><div class="v">{len(report.hosts)}</div></div>
</div>

<div class="card">
  <h2>Discovery Sources (resolved)</h2>
  <table>
    <thead><tr><th>FQDN</th><th>IPs</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(drows)}</tbody>
  </table>
</div>

<div class="card">
  <h2>Hosts</h2>
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>Ports (port/service)</th><th>Count</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>

<div class="card" style="color:var(--muted);font-size:12px">
  Started: <span class="mono">{html_escape(report.started_at)}</span> |
  Finished: <span class="mono">{html_escape(report.finished_at)}</span><br/>
  Credits: {html_escape(CREDITS_NAME)} — <a href="{html_escape(CREDITS_LINKEDIN)}">LinkedIn</a> • <a href="{html_escape(CREDITS_GITHUB)}">GitHub</a>
</div>
</body></html>"""

def write_html_reports(report_name: str, html_dir: str, report: ScanReport) -> str:
    Path(html_dir).mkdir(parents=True, exist_ok=True)
    html_files: List[Tuple[str, HostReport]] = []

    for hr in report.hosts:
        fname = f"{report_name}_{safe_filename(hr.name)}_{safe_filename(hr.ip)}.html"
        fpath = Path(html_dir) / fname
        fpath.write_text(build_host_html(report.target, report_name, hr), encoding="utf-8")
        html_files.append((fname, hr))

    index_name = f"{report_name}_index.html"
    index_path = Path(html_dir) / index_name
    index_path.write_text(build_index_html(report, html_files), encoding="utf-8")

    return str(index_path)


# -------------------- Main (AUTO) --------------------
async def main() -> None:
    if len(sys.argv) < 4 or any(x in sys.argv for x in ("-h", "--help")):
        print(BANNER)
        print("Usage:\n  python3 zonestrike.py <TARGET> <TOP_N_PORTS> <REPORT_NAME>\n")
        print("Example:\n  python3 zonestrike.py lab.local 100 lab_report\n")
        sys.exit(1)

    target = sys.argv[1].strip()
    try:
        top_n = int(sys.argv[2])
        if top_n < 1 or top_n > 65535:
            raise ValueError()
    except Exception:
        print("[!] TOP_N_PORTS inválido. Use 1..65535")
        sys.exit(2)

    report_name = sys.argv[3].strip()
    if not report_name:
        print("[!] REPORT_NAME inválido.")
        sys.exit(2)

    print(BANNER)

    started = now_iso()

    nmap_services = find_nmap_services_file()
    if not nmap_services:
        print("[!] nmap-services não encontrado. Instale nmap: sudo apt install nmap")
        sys.exit(2)

    svc_map = load_nmap_services_map(nmap_services)
    ports = top_ports_from_nmap_services(nmap_services, top_n)

    # Auto discovery
    discovery, ip_to_name = run_discovery(target, timeout=3.0)
    all_ips = uniq([ip for d in discovery for ip in d.ips])

    print(f"[+] Discovery resolved FQDNs: {len(discovery)} | Unique IPs: {len(all_ips)}")
    wl = pick_default_wordlist()
    if wl:
        print(f"[+] Auto wordlist loaded: {wl}")
    else:
        print("[+] Auto wordlist: not found (ok). Create wordlists/basic.txt to enable.")

    # Scan defaults (moderados)
    host_concurrency = 10
    port_concurrency = 200
    tcp_timeout = 1.2
    banner_timeout = 1.8
    http_timeout = 2.2
    ua = f"ZoneStrike/{VERSION} (authorized testing)"

    async def scan_ip(ip: str, sem: asyncio.Semaphore) -> HostReport:
        async with sem:
            name = ip_to_name.get(ip, target)
            open_ports = await scan_open_ports(ip, ports, port_concurrency, tcp_timeout)
            if not open_ports:
                return HostReport(ip=ip, name=name, open_ports=[], errors=[])
            enriched = await enrich_ports(ip, open_ports, svc_map, banner_timeout, http_timeout, ua)
            return HostReport(ip=ip, name=name, open_ports=enriched, errors=[])

    sem = asyncio.Semaphore(host_concurrency)
    host_reports = await asyncio.gather(*[asyncio.create_task(scan_ip(ip, sem)) for ip in all_ips])
    host_reports.sort(key=lambda x: (x.name, x.ip))

    finished = now_iso()

    report = ScanReport(
        target=target,
        top_n_ports=top_n,
        ports_count=len(ports),
        discovered_fqdns=len(discovery),
        discovered_ips=len(all_ips),
        discovery=discovery,
        hosts=host_reports,
        started_at=started,
        finished_at=finished,
    )

    # Outputs
    json_path = f"{report_name}.json"
    csv_path = f"{report_name}.csv"
    write_json(json_path, report)
    write_csv(csv_path, report)

    print(f"[+] Reports written: {json_path} and {csv_path}")

    html_dir = "reports"
    index_path = write_html_reports(report_name, html_dir, report)
    abs_index = os.path.abspath(index_path)
    file_url = "file://" + quote(abs_index)

    print(f"[+] HTML written: ./{html_dir}")
    print(f"[+] Open report: {file_url}")

    # Try open
    try:
        webbrowser.open(file_url)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
