#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneStrike v1.5.1 — AXFR + TCP Port Scan + Rich Reports (JSON/CSV/HTML)

Legal: Use ONLY with explicit authorization.

Key features:
- NS auto-discovery OR explicit --ns (IP/hostname)
- AXFR attempt across NS candidates
- A-record resolve with fallback (NS -> system resolver)
- Two-phase scan (open ports -> enrichment only for open ports)
- Safe scanning for "all ports" using Queue workers (no 65k tasks explosion)
- nmap-services mapping + banner parsing + evidence/confidence fields
- Rich HTML reports (index + per-host) in --html-dir and clickable file:// link printed
- Guardrails: --max-hosts, --max-ports, --max-total-seconds, --max-host-seconds
- Terminal summary: --summary
"""

import argparse
import asyncio
import csv
import json
import os
import random
import re
import ssl
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import dns.query
import dns.resolver
import dns.zone

VERSION = "1.5.1"

BANNER = r"""
███████╗ ██████╗ ███╗   ██╗███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
███████╗╚██████╔╝██║ ╚████║███████╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

ZoneStrike v1.5.1 — AXFR + Port Scan + Rich Reporting
Use ONLY with explicit authorization.
"""


# -------------------- Data Models --------------------
@dataclass
class PortFinding:
    port: int
    proto: str
    state: str

    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os_hint: Optional[str] = None
    confidence: Optional[str] = None  # high/medium/low
    evidence: Optional[str] = None    # banner/http/nmap-services

    banner: Optional[str] = None

    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None


@dataclass
class HostReport:
    host: str
    resolved_name: Optional[str]
    open_ports: List[PortFinding]
    errors: List[str]


@dataclass
class ScanReport:
    target_domain: str
    nameservers_used: List[str]
    nameserver_success: Optional[str]
    axfr_success: bool
    discovered_names: List[str]
    discovered_ips: List[str]
    ports_profile: str
    ports_count: int
    hosts: List[HostReport]
    started_at: str
    finished_at: str
    version: str = VERSION


# -------------------- Constants --------------------
DEFAULT_NMAP_SERVICES_PATHS = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]

LIKELY_WEB_PORTS_PLAIN = {80, 8080, 8000, 8888, 3000, 10000}
LIKELY_WEB_PORTS_TLS = {443, 8443, 9443}


# -------------------- Utils --------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_decode(b: bytes, limit: int = 800) -> str:
    s = b.decode("utf-8", errors="replace")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s[:limit]

def uniq_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def parse_ports(s: str) -> List[int]:
    ports: Set[int] = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            a, b = int(a), int(b)
            lo, hi = min(a, b), max(a, b)
            for x in range(lo, hi + 1):
                if 1 <= x <= 65535:
                    ports.add(x)
        else:
            x = int(p)
            if 1 <= x <= 65535:
                ports.add(x)
    return sorted(ports)

def load_ports_from_file(path: str) -> List[int]:
    raw = Path(path).read_text(encoding="utf-8", errors="ignore")
    raw = raw.replace("\n", ",").replace("\r", ",").strip()
    if not raw:
        return []
    return parse_ports(",".join([x.strip() for x in raw.split(",") if x.strip()]))

def safe_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)

def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

def clamp_int(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


# -------------------- nmap-services helpers --------------------
def find_nmap_services_file(custom_path: Optional[str] = None) -> Optional[str]:
    if custom_path:
        p = Path(custom_path)
        return str(p) if p.exists() else None
    for p in DEFAULT_NMAP_SERVICES_PATHS:
        if Path(p).exists():
            return p
    return None

def load_nmap_services_map(path: Optional[str]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if not path:
        return out
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    rx = re.compile(r"^\s*([^\s]+)\s+(\d+)\/(tcp|udp)\s+([0-9.]+)")
    for line in text.splitlines():
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

def top_ports_from_nmap_services(n: int, path: str) -> List[int]:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    rx = re.compile(r"^\s*([^\s]+)\s+(\d+)\/(tcp|udp)\s+([0-9.]+)")
    rows: List[Tuple[float, int]] = []
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if not m:
            continue
        port = int(m.group(2))
        proto = m.group(3)
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

def select_ports(profile: str, custom: str, ports_file: str, nmap_services_path: Optional[str]) -> List[int]:
    if profile in ("top100", "top1000"):
        if not nmap_services_path:
            raise FileNotFoundError("nmap-services not found. Install nmap or provide --nmap-services-path.")
        return top_ports_from_nmap_services(100 if profile == "top100" else 1000, nmap_services_path)
    if profile == "all":
        return list(range(1, 65536))
    if profile == "custom":
        if not custom:
            raise ValueError("Use --ports when --port-profile=custom")
        return parse_ports(custom)
    if profile == "file":
        if not ports_file:
            raise ValueError("Use --ports-file when --port-profile=file")
        ports = load_ports_from_file(ports_file)
        if not ports:
            raise ValueError("Ports file is empty/invalid.")
        return ports
    raise ValueError("Invalid port profile")


# -------------------- DNS / NS discovery / resolve --------------------
def discover_authoritative_ns(domain: str, timeout: float = 3.0) -> Tuple[List[str], List[str]]:
    """
    Returns (ns_names, ns_ips)
    """
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    try:
        ans = r.resolve(domain, "NS")
        ns_names = [rr.to_text().rstrip(".") for rr in ans]
    except Exception:
        return [], []

    ips: List[str] = []
    for ns in ns_names:
        try:
            a = r.resolve(ns, "A")
            ips.extend([rr.to_text() for rr in a])
        except Exception:
            pass
        try:
            aaaa = r.resolve(ns, "AAAA")
            ips.extend([rr.to_text() for rr in aaaa])
        except Exception:
            pass

    return uniq_keep_order(ns_names), uniq_keep_order([ip for ip in ips if ip])

def resolve_ns_to_ip(ns: str, timeout: float = 3.0) -> List[str]:
    """
    If user passes --ns as hostname, resolve it.
    """
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    ips: List[str] = []
    try:
        a = r.resolve(ns, "A")
        ips.extend([rr.to_text() for rr in a])
    except Exception:
        pass
    try:
        aaaa = r.resolve(ns, "AAAA")
        ips.extend([rr.to_text() for rr in aaaa])
    except Exception:
        pass
    return uniq_keep_order([ip for ip in ips if ip])

def do_axfr(domain: str, nameserver_ip: str, timeout: float = 10.0) -> Tuple[bool, List[str], str]:
    try:
        xfr = dns.query.xfr(where=nameserver_ip, zone=domain, timeout=timeout, lifetime=timeout)
        z = dns.zone.from_xfr(xfr)
        names: List[str] = []
        for name, _node in z.nodes.items():
            fqdn = f"{name}.{domain}".replace("@.", "").strip(".")
            if fqdn:
                names.append(fqdn)
        return True, uniq_keep_order(names), ""
    except Exception as e:
        return False, [], str(e)

def resolve_names_to_ips_with_fallback(
    names: List[str],
    preferred_ns_ip: str,
    timeout: float = 3.0
) -> Dict[str, List[str]]:
    """
    Try to resolve using preferred NS as resolver, and fallback to system resolver
    if it doesn't answer (common when NS isn't recursive).
    """
    out: Dict[str, List[str]] = {}

    # 1) Try NS as resolver
    r_ns = dns.resolver.Resolver(configure=False)
    r_ns.nameservers = [preferred_ns_ip]
    r_ns.timeout = timeout
    r_ns.lifetime = timeout

    # 2) System resolver
    r_sys = dns.resolver.Resolver()
    r_sys.timeout = timeout
    r_sys.lifetime = timeout

    for n in names:
        ips: List[str] = []
        try:
            ans = r_ns.resolve(n, "A")
            ips = [a.to_text() for a in ans]
        except Exception:
            ips = []

        if not ips:
            try:
                ans = r_sys.resolve(n, "A")
                ips = [a.to_text() for a in ans]
            except Exception:
                ips = []

        out[n] = uniq_keep_order([ip for ip in ips if ip])

    return out


# -------------------- Timers --------------------
async def run_with_timeout(coro, seconds: float, label: str) -> Tuple[bool, Optional[object], Optional[str]]:
    try:
        if seconds and seconds > 0:
            res = await asyncio.wait_for(coro, timeout=seconds)
        else:
            res = await coro
        return True, res, None
    except asyncio.TimeoutError:
        return False, None, f"timeout: {label} exceeded {seconds}s"
    except Exception as e:
        return False, None, f"error: {label}: {e}"


# -------------------- Scan Phase 1 (SAFE workers, no task explosion) --------------------
async def try_connect(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_open_ports(host: str, ports: List[int], concurrency: int, timeout: float) -> List[int]:
    """
    Worker-queue model: safe even for 65k ports.
    """
    concurrency = clamp_int(concurrency, 1, 2000)
    q: asyncio.Queue[int] = asyncio.Queue()
    for p in ports:
        q.put_nowait(p)

    open_ports: List[int] = []
    lock = asyncio.Lock()

    async def worker() -> None:
        while True:
            try:
                p = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if await try_connect(host, p, timeout):
                    async with lock:
                        open_ports.append(p)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*workers)
    open_ports.sort()
    return open_ports


# -------------------- Service identification (banner parsing + defaults) --------------------
def identify_from_banner(banner: str) -> Dict[str, Optional[str]]:
    b = banner or ""

    # SSH: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
    m = re.search(r"^SSH-\d+\.\d+-([A-Za-z0-9._-]+)", b)
    if m:
        ident = m.group(1)
        product, version, os_hint = None, None, None
        m2 = re.search(r"(OpenSSH)[_-]([0-9A-Za-z.]+)", ident)
        if m2:
            product = m2.group(1)
            version = m2.group(2)
        tail = b.split(ident, 1)[-1].strip()
        if tail:
            os_hint = tail[:120]
        return dict(service_name="ssh", product=product or ident, version=version, os_hint=os_hint,
                    confidence="high", evidence="banner")

    # FTP greeting
    if b.startswith("220 "):
        m = re.search(r"220\s+([A-Za-z0-9._-]+)\s+([0-9][0-9A-Za-z.]+)", b)
        if m:
            return dict(service_name="ftp", product=m.group(1), version=m.group(2), os_hint=None,
                        confidence="high", evidence="banner")
        return dict(service_name="ftp", product=None, version=None, os_hint=None,
                    confidence="medium", evidence="banner")

    # POP3
    if b.startswith("+OK"):
        return dict(service_name="pop3", product=None, version=None, os_hint=None,
                    confidence="medium", evidence="banner")

    # IMAP
    if b.startswith("* OK"):
        if "Courier-IMAP" in b:
            return dict(service_name="imap", product="Courier-IMAP", version=None, os_hint=None,
                        confidence="high", evidence="banner")
        return dict(service_name="imap", product=None, version=None, os_hint=None,
                    confidence="medium", evidence="banner")

    # SMTP (rough)
    if re.search(r"^220\s+.*(ESMTP|SMTP)", b, re.IGNORECASE):
        return dict(service_name="smtp", product=None, version=None, os_hint=None,
                    confidence="medium", evidence="banner")

    return {}

def fill_service_defaults(pf: PortFinding, svc_map: Dict[int, str]) -> None:
    if pf.service_name:
        return
    svc = svc_map.get(pf.port)
    if svc:
        pf.service_name = svc
        pf.confidence = pf.confidence or "low"
        pf.evidence = pf.evidence or "nmap-services"


# -------------------- Enrichment (Phase 2) --------------------
async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(240), timeout=0.9)
            if data:
                banner = safe_decode(data)
        except Exception:
            banner = None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner
    except Exception:
        return None

async def http_probe(host: str, port: int, use_tls: bool, user_agent: str, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Note: UA is used only for HTTP probe (not for TCP connect scans).
    """
    try:
        ssl_ctx = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout)

        req = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

        writer.write(req)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        text = data.decode("utf-8", errors="replace")

        status = None
        m = re.search(r"HTTP\/\d\.\d\s+(\d{3})", text)
        if m:
            status = int(m.group(1))

        server = None
        m = re.search(r"(?im)^Server:\s*(.+)$", text)
        if m:
            server = m.group(1).strip()

        title = None
        # Optional GET to get title (best effort, keep it small)
        try:
            reader2, writer2 = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout)
            req2 = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {user_agent}\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()
            writer2.write(req2)
            await writer2.drain()
            html = await asyncio.wait_for(reader2.read(4096), timeout=timeout)
            html_text = html.decode("utf-8", errors="replace")
            mt = re.search(r"(?is)<title>\s*(.*?)\s*</title>", html_text)
            if mt:
                title = re.sub(r"\s+", " ", mt.group(1).strip())[:140]
            writer2.close()
            try:
                await writer2.wait_closed()
            except Exception:
                pass
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return status, server, title
    except Exception:
        return None, None, None

async def enrich_open_ports(
    host: str,
    open_ports: List[int],
    banner_timeout: float,
    do_http_probe: bool,
    http_timeout: float,
    user_agent: str,
    svc_map: Dict[int, str],
    mode: str,
    concurrency: int,
) -> List[PortFinding]:
    findings: List[PortFinding] = []

    async def enrich_one(p: int) -> None:
        pf = PortFinding(port=p, proto="tcp", state="open")

        pf.banner = await grab_banner(host, p, banner_timeout)
        if pf.banner:
            ident = identify_from_banner(pf.banner)
            if ident:
                pf.service_name = ident.get("service_name")
                pf.product = ident.get("product")
                pf.version = ident.get("version")
                pf.os_hint = ident.get("os_hint")
                pf.confidence = ident.get("confidence")
                pf.evidence = ident.get("evidence")

        if do_http_probe and (p in LIKELY_WEB_PORTS_PLAIN or p in LIKELY_WEB_PORTS_TLS):
            tls = p in LIKELY_WEB_PORTS_TLS
            st, sv, title = await http_probe(host, p, tls, user_agent, http_timeout)
            pf.http_status = st
            pf.http_server = sv
            pf.http_title = title
            if (st is not None or sv or title) and not pf.service_name:
                pf.service_name = "https" if tls else "http"
                pf.confidence = pf.confidence or "medium"
                pf.evidence = pf.evidence or "http"
            if sv and not pf.product:
                pf.product = sv

        fill_service_defaults(pf, svc_map)
        findings.append(pf)

    if mode == "serial":
        for p in open_ports:
            await enrich_one(p)
        findings.sort(key=lambda x: x.port)
        return findings

    sem = asyncio.Semaphore(clamp_int(concurrency, 1, 200))

    async def wrapped(p: int) -> None:
        async with sem:
            await enrich_one(p)

    await asyncio.gather(*[asyncio.create_task(wrapped(p)) for p in open_ports])
    findings.sort(key=lambda x: x.port)
    return findings


# -------------------- Reporting (JSON/CSV) --------------------
def write_json(path: str, report: ScanReport) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, ensure_ascii=False, indent=2)

def write_csv(path: str, report: ScanReport) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "host", "resolved_name",
            "port", "proto", "state",
            "service_name", "product", "version", "os_hint", "confidence", "evidence",
            "banner",
            "http_status", "http_server", "http_title"
        ])
        for hr in report.hosts:
            for pf in hr.open_ports:
                w.writerow([
                    hr.host,
                    hr.resolved_name or "",
                    pf.port, pf.proto, pf.state,
                    pf.service_name or "",
                    pf.product or "",
                    pf.version or "",
                    pf.os_hint or "",
                    pf.confidence or "",
                    pf.evidence or "",
                    pf.banner or "",
                    pf.http_status if pf.http_status is not None else "",
                    pf.http_server or "",
                    pf.http_title or "",
                ])


# -------------------- HTML Reporting (rich) --------------------
def compute_insights(report: ScanReport) -> Dict[str, object]:
    port_count: Dict[int, int] = {}
    svc_count: Dict[str, int] = {}
    banners: Set[str] = set()
    most_exposed: List[Tuple[str, int]] = []

    for hr in report.hosts:
        most_exposed.append(((hr.resolved_name or hr.host), len(hr.open_ports)))
        for pf in hr.open_ports:
            port_count[pf.port] = port_count.get(pf.port, 0) + 1
            if pf.service_name:
                svc_count[pf.service_name] = svc_count.get(pf.service_name, 0) + 1
            if pf.banner:
                banners.add(pf.banner)

    top_ports = sorted(port_count.items(), key=lambda x: (-x[1], x[0]))[:12]
    top_svcs = sorted(svc_count.items(), key=lambda x: (-x[1], x[0]))[:12]
    most_exposed.sort(key=lambda x: (-x[1], x[0]))
    most_exposed = most_exposed[:10]

    return {
        "top_ports": top_ports,
        "top_services": top_svcs,
        "unique_banners": sorted(list(banners))[:25],
        "most_exposed": most_exposed,
    }

def build_host_html(report: ScanReport, host: HostReport) -> str:
    host_id = host.resolved_name or host.host
    title = f"ZoneStrike — {report.target_domain} — {host_id}"

    rows = []
    for pf in host.open_ports:
        banner = pf.banner or ""
        rows.append(
            "<tr>"
            f"<td class='mono'>{pf.port}</td>"
            f"<td>{html_escape(pf.service_name or '')}</td>"
            f"<td>{html_escape(pf.product or '')}</td>"
            f"<td>{html_escape(pf.version or '')}</td>"
            f"<td>{html_escape(pf.os_hint or '')}</td>"
            f"<td>{html_escape(pf.confidence or '')}</td>"
            f"<td>{html_escape(pf.evidence or '')}</td>"
            f"<td class='mono'>{html_escape(str(pf.http_status) if pf.http_status is not None else '')}</td>"
            f"<td>{html_escape(pf.http_server or '')}</td>"
            f"<td>{html_escape(pf.http_title or '')}</td>"
            f"<td><details><summary>view</summary><pre class='pre'>{html_escape(banner)}</pre></details></td>"
            "</tr>"
        )

    errors_html = ""
    if host.errors:
        items = "".join(f"<li><span class='mono'>{html_escape(e)}</span></li>" for e in host.errors)
        errors_html = f"<div class='card'><h3>Errors</h3><ul>{items}</ul></div>"

    summary_ports = ", ".join(str(p.port) for p in host.open_ports) if host.open_ports else "None"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html_escape(title)}</title>
<style>
  :root {{
    --bg: #0b0f17;
    --card: #111827;
    --muted: #9CA3AF;
    --text: #E5E7EB;
    --line: rgba(255,255,255,.08);
    --accent: #60A5FA;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: ui-sans-serif, system-ui, Arial; margin: 24px; }}
  a {{ color: var(--accent); }}
  .small {{ color: var(--muted); font-size: 12px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  .grid {{ display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 12px; margin: 16px 0; }}
  .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
  th, td {{ border-bottom: 1px solid var(--line); text-align: left; padding: 10px; vertical-align: top; }}
  th {{ background: rgba(255,255,255,.03); color: var(--muted); font-size: 12px; }}
  details summary {{ cursor: pointer; color: var(--accent); }}
  .pre {{ margin: 8px 0 0 0; white-space: pre-wrap; word-break: break-word; color: var(--text); }}
  .k {{ color: var(--muted); font-size: 12px; }}
  .v {{ font-size: 20px; font-weight: 700; margin-top: 6px; }}
</style>
</head>
<body>
  <h1>ZoneStrike — Host Report</h1>
  <div class="small">Target: <span class="mono">{html_escape(report.target_domain)}</span> | Version: <span class="mono">{html_escape(report.version)}</span></div>

  <div class="grid">
    <div class="card"><div class="k">Host</div><div class="v">{html_escape(host_id)}</div><div class="small mono">{html_escape(host.host)}</div></div>
    <div class="card"><div class="k">Open ports</div><div class="v">{len(host.open_ports)}</div><div class="small mono">{html_escape(summary_ports)}</div></div>
    <div class="card"><div class="k">AXFR</div><div class="v">{html_escape(str(report.axfr_success))}</div><div class="small mono">{html_escape(report.nameserver_success or "None")}</div></div>
  </div>

  <h2>Open Ports</h2>
  <table>
    <thead>
      <tr>
        <th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>OS Hint</th>
        <th>Confidence</th><th>Evidence</th><th>HTTP</th><th>Server</th><th>Title</th><th>Banner</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="11">No open ports found.</td></tr>'}
    </tbody>
  </table>

  {errors_html}

  <div class="card" style="margin-top:16px">
    <div class="small"><strong>Started:</strong> <span class="mono">{html_escape(report.started_at)}</span> |
    <strong>Finished:</strong> <span class="mono">{html_escape(report.finished_at)}</span></div>
    <div class="small"><strong>Legal:</strong> authorized testing only.</div>
  </div>
</body>
</html>"""

def build_index_html(report: ScanReport, host_files: List[Tuple[str, HostReport]]) -> str:
    insights = compute_insights(report)

    host_rows = []
    for rel_file, hr in host_files:
        host_label = hr.resolved_name or hr.host
        open_ports = ", ".join(str(p.port) for p in hr.open_ports) if hr.open_ports else "None"
        host_rows.append(
            "<tr>"
            f"<td><a href='{html_escape(rel_file)}'>{html_escape(host_label)}</a></td>"
            f"<td class='mono'>{html_escape(hr.host)}</td>"
            f"<td class='mono'>{html_escape(open_ports)}</td>"
            f"<td class='mono'>{len(hr.open_ports)}</td>"
            "</tr>"
        )

    top_ports_rows = "".join(
        f"<tr><td class='mono'>{p}</td><td class='mono'>{c}</td></tr>" for p, c in insights["top_ports"]
    ) or "<tr><td colspan='2'>None</td></tr>"

    top_services_rows = "".join(
        f"<tr><td class='mono'>{html_escape(s)}</td><td class='mono'>{c}</td></tr>" for s, c in insights["top_services"]
    ) or "<tr><td colspan='2'>None</td></tr>"

    most_exposed_rows = "".join(
        f"<tr><td>{html_escape(h)}</td><td class='mono'>{c}</td></tr>" for h, c in insights["most_exposed"]
    ) or "<tr><td colspan='2'>None</td></tr>"

    unique_banners = insights["unique_banners"]
    banners_html = "".join(f"<li><span class='mono'>{html_escape(b)}</span></li>" for b in unique_banners) or "<li>None</li>"

    title = f"ZoneStrike — Report Index — {report.target_domain}"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html_escape(title)}</title>
<style>
  :root {{
    --bg: #0b0f17;
    --card: #111827;
    --muted: #9CA3AF;
    --text: #E5E7EB;
    --line: rgba(255,255,255,.08);
    --accent: #60A5FA;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: ui-sans-serif, system-ui, Arial; margin: 24px; }}
  a {{ color: var(--accent); }}
  h1,h2,h3 {{ margin: 0 0 12px 0; }}
  .small {{ color: var(--muted); font-size: 12px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  .grid {{ display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 12px; margin: 16px 0; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0; }}
  .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px; }}
  .k {{ color: var(--muted); font-size: 12px; }}
  .v {{ font-size: 22px; font-weight: 700; margin-top: 6px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
  th, td {{ border-bottom: 1px solid var(--line); text-align: left; padding: 10px; vertical-align: top; }}
  th {{ background: rgba(255,255,255,.03); color: var(--muted); font-size: 12px; }}
  ul {{ margin: 0; padding-left: 18px; }}
</style>
</head>
<body>
  <h1>ZoneStrike — Report Index</h1>
  <div class="small">Target: <span class="mono">{html_escape(report.target_domain)}</span> | Version: <span class="mono">{html_escape(report.version)}</span></div>

  <div class="grid">
    <div class="card"><div class="k">AXFR</div><div class="v">{html_escape(str(report.axfr_success))}</div><div class="small mono">NS: {html_escape(report.nameserver_success or "None")}</div></div>
    <div class="card"><div class="k">Names</div><div class="v">{len(report.discovered_names)}</div><div class="small">from zone</div></div>
    <div class="card"><div class="k">IPs</div><div class="v">{len(report.discovered_ips)}</div><div class="small">unique</div></div>
    <div class="card"><div class="k">Ports scanned</div><div class="v">{report.ports_count}</div><div class="small">{html_escape(report.ports_profile)}</div></div>
  </div>

  <div class="grid2">
    <div class="card">
      <h3>Top Ports</h3>
      <table><thead><tr><th>Port</th><th>Hosts</th></tr></thead><tbody>{top_ports_rows}</tbody></table>
    </div>
    <div class="card">
      <h3>Top Services</h3>
      <table><thead><tr><th>Service</th><th>Count</th></tr></thead><tbody>{top_services_rows}</tbody></table>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h3>Most Exposed Hosts</h3>
      <table><thead><tr><th>Host</th><th>Open ports</th></tr></thead><tbody>{most_exposed_rows}</tbody></table>
    </div>
    <div class="card">
      <h3>Unique Banners (sample)</h3>
      <ul>{banners_html}</ul>
      <div class="small" style="margin-top:8px;">(limited sample to keep file small)</div>
    </div>
  </div>

  <div class="card">
    <h2>Hosts</h2>
    <table>
      <thead><tr><th>Host</th><th>IP</th><th>Open ports</th><th>Count</th></tr></thead>
      <tbody>{''.join(host_rows) if host_rows else '<tr><td colspan="4">No hosts.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="small">
      <strong>Started:</strong> <span class="mono">{html_escape(report.started_at)}</span> |
      <strong>Finished:</strong> <span class="mono">{html_escape(report.finished_at)}</span>
    </div>
    <div class="small"><strong>Legal:</strong> authorized testing only.</div>
  </div>
</body>
</html>"""

def write_html_reports(out_base: str, html_dir: str, report: ScanReport) -> Tuple[List[str], str]:
    Path(html_dir).mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    host_files: List[Tuple[str, HostReport]] = []

    for hr in report.hosts:
        host_id = hr.resolved_name or hr.host
        fname = f"{out_base}_{safe_filename(host_id)}.html"
        out_path = Path(html_dir) / fname
        out_path.write_text(build_host_html(report, hr), encoding="utf-8")
        written.append(str(out_path))
        host_files.append((fname, hr))

    index_name = f"{out_base}_index.html"
    index_path = Path(html_dir) / index_name
    index_path.write_text(build_index_html(report, host_files), encoding="utf-8")
    written.append(str(index_path))

    return written, str(index_path)


# -------------------- Terminal Summary --------------------
def print_summary(report: ScanReport) -> None:
    insights = compute_insights(report)
    print("\n[+] Summary:")
    print(f"    - Hosts: {len(report.hosts)} | Unique IPs: {len(report.discovered_ips)} | Names: {len(report.discovered_names)}")
    if insights["top_ports"]:
        top_ports = ", ".join(f"{p}({c})" for p, c in insights["top_ports"][:8])
        print(f"    - Top ports: {top_ports}")
    if insights["top_services"]:
        top_svcs = ", ".join(f"{s}({c})" for s, c in insights["top_services"][:8])
        print(f"    - Top services: {top_svcs}")
    if insights["most_exposed"]:
        h, c = insights["most_exposed"][0]
        print(f"    - Most exposed: {h} ({c} open ports)")
    print("")


# -------------------- Main --------------------
async def main() -> None:
    ap = argparse.ArgumentParser(description="ZoneStrike — AXFR + TCP Port Scanner (authorized testing only).")

    ap.add_argument("--domain", required=True, help="Domain/zone (e.g. example.com)")
    ap.add_argument("--ns", default="", help="Authoritative NS IP or hostname (optional). If omitted, auto-discovery is used.")

    ap.add_argument("--port-profile", choices=["top100", "top1000", "all", "custom", "file"], default="top1000")
    ap.add_argument("--ports", default="", help="Used with custom. Example: 1-1024,3306,8080")
    ap.add_argument("--ports-file", default="", help="Used with file.")
    ap.add_argument("--nmap-services-path", default="", help="Path to nmap-services (optional).")

    # Defaults lowered a bit to reduce accidental overload
    ap.add_argument("--host-concurrency", type=int, default=10, help="Hosts in parallel (phase 1)")
    ap.add_argument("--port-concurrency", type=int, default=200, help="Ports per host in parallel (phase 1)")
    ap.add_argument("--timeout", type=float, default=1.2, help="TCP connect timeout seconds (phase 1)")

    ap.add_argument("--delay", type=float, default=0.0, help="Delay (sec) before scanning each host.")
    ap.add_argument("--jitter", type=float, default=0.0, help="Random jitter (sec) added to delay.")

    ap.add_argument("--axfr-timeout", type=float, default=10.0, help="AXFR timeout seconds")
    ap.add_argument("--dns-timeout", type=float, default=3.0, help="DNS resolve timeout seconds")

    ap.add_argument("--list-hosts", action="store_true", help="Print discovered hostnames and IPs before scanning.")

    # Phase 2
    ap.add_argument("--enrich", action="store_true", help="Enrich open ports (banners + optional HTTP probe).")
    ap.add_argument("--enrich-mode", choices=["serial", "parallel"], default="serial")
    ap.add_argument("--enrich-concurrency", type=int, default=20)
    ap.add_argument("--banner-timeout", type=float, default=1.8)
    ap.add_argument("--http-probe", action="store_true", help="HTTP probe on common web ports (only in enrichment).")
    ap.add_argument("--user-agent", default=f"ZoneStrike/{VERSION} (authorized testing)",
                    help="UA used only for HTTP probe (not for TCP connect scans).")
    ap.add_argument("--http-timeout", type=float, default=2.2)

    # Guardrails
    ap.add_argument("--max-hosts", type=int, default=0, help="Limit number of IPs scanned (0 = no limit).")
    ap.add_argument("--max-ports", type=int, default=0, help="Limit number of ports scanned (0 = no limit).")
    ap.add_argument("--max-host-seconds", type=float, default=0.0, help="Max seconds per host (0 disables).")
    ap.add_argument("--max-total-seconds", type=float, default=0.0, help="Max seconds for the whole run (0 disables).")

    ap.add_argument("--out", default="zonestrike_report", help="Output base name")
    ap.add_argument("--html", action="store_true", help="Generate HTML reports (per-host + index).")
    ap.add_argument("--html-dir", default="reports", help="Directory for HTML reports.")
    ap.add_argument("--summary", action="store_true", help="Print terminal summary at the end.")

    ap.add_argument("--no-banner", action="store_true")

    args = ap.parse_args()

    if not args.no_banner:
        print(BANNER)

    started = now_iso()

    # nmap-services map
    nmap_path = args.nmap_services_path.strip() or find_nmap_services_file(None)
    svc_map = load_nmap_services_map(nmap_path) if nmap_path else {}

    # Ports selection
    ports = select_ports(args.port_profile, args.ports, args.ports_file, nmap_path)

    if args.max_ports and args.max_ports > 0:
        ports = ports[:max(1, args.max_ports)]

    # Determine NS IPs candidates
    ns_ips: List[str] = []
    ns_used: List[str] = []

    if args.ns.strip():
        ns_used = [args.ns.strip()]
        # user might pass hostname; resolve to IPs
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", args.ns.strip()):
            ns_ips = [args.ns.strip()]
        else:
            ns_ips = resolve_ns_to_ip(args.ns.strip(), timeout=float(args.dns_timeout))
    else:
        _ns_names, ns_ips = discover_authoritative_ns(args.domain, timeout=float(args.dns_timeout))
        ns_used = ns_ips[:]  # store attempted list for report

    ns_ips = uniq_keep_order([ip for ip in ns_ips if ip])
    ns_used = uniq_keep_order([x for x in ns_used if x])

    if not ns_ips:
        finished = now_iso()
        report = ScanReport(
            target_domain=args.domain,
            nameservers_used=ns_used,
            nameserver_success=None,
            axfr_success=False,
            discovered_names=[],
            discovered_ips=[],
            ports_profile=args.port_profile,
            ports_count=len(ports),
            hosts=[],
            started_at=started,
            finished_at=finished,
        )
        write_json(f"{args.out}.json", report)
        write_csv(f"{args.out}.csv", report)
        print("[!] Could not determine any NS IPs. Pass --ns or check DNS.")
        return

    # AXFR attempt across NS IPs
    axfr_ok = False
    names: List[str] = []
    ns_success: Optional[str] = None
    axfr_errors: List[str] = []

    for ns_ip in ns_ips:
        ok, n, err = do_axfr(args.domain, ns_ip, timeout=float(args.axfr_timeout))
        if ok:
            axfr_ok = True
            names = n
            ns_success = ns_ip
            break
        axfr_errors.append(f"{ns_ip}: {err}")

    if not axfr_ok or not ns_success:
        finished = now_iso()
        report = ScanReport(
            target_domain=args.domain,
            nameservers_used=ns_used if ns_used else ns_ips,
            nameserver_success=None,
            axfr_success=False,
            discovered_names=[],
            discovered_ips=[],
            ports_profile=args.port_profile,
            ports_count=len(ports),
            hosts=[],
            started_at=started,
            finished_at=finished,
        )
        write_json(f"{args.out}.json", report)
        write_csv(f"{args.out}.csv", report)
        print("[!] AXFR failed on all NS candidates.")
        for e in axfr_errors[:3]:
            print(f"    - {e}")
        return

    # Resolve hostnames -> IPs with fallback
    name_to_ips = resolve_names_to_ips_with_fallback(names, ns_success, timeout=float(args.dns_timeout))

    ips: List[str] = []
    for iplist in name_to_ips.values():
        ips.extend(iplist)
    ips = uniq_keep_order([ip for ip in ips if ip])

    if args.max_hosts and args.max_hosts > 0:
        ips = ips[:max(1, args.max_hosts)]

    ip_to_name: Dict[str, str] = {}
    for fqdn, iplist in name_to_ips.items():
        for ip in iplist:
            if ip and ip not in ip_to_name:
                ip_to_name[ip] = fqdn

    if args.list_hosts:
        print("\n[+] Discovered hosts (FQDN -> IPs):")
        for fqdn in sorted(name_to_ips.keys()):
            iplist = name_to_ips.get(fqdn, [])
            print(f"    - {fqdn} -> {', '.join(iplist) if iplist else '(no A record)'}")
        print(f"[+] Unique IPs: {len(ips)}\n")

    async def do_scan() -> List[HostReport]:
        host_sem = asyncio.Semaphore(clamp_int(args.host_concurrency, 1, 200))
        hosts_reports: List[HostReport] = []

        async def scan_one_host(ip: str) -> None:
            async with host_sem:
                errors: List[str] = []

                if args.delay > 0 or args.jitter > 0:
                    await asyncio.sleep(max(0.0, args.delay) + (random.random() * max(0.0, args.jitter)))

                async def per_host_task() -> HostReport:
                    open_ports = await scan_open_ports(
                        ip, ports=ports,
                        concurrency=args.port_concurrency,
                        timeout=float(args.timeout),
                    )

                    if not open_ports:
                        return HostReport(host=ip, resolved_name=ip_to_name.get(ip), open_ports=[], errors=[])

                    if args.enrich:
                        enriched = await enrich_open_ports(
                            host=ip,
                            open_ports=open_ports,
                            banner_timeout=float(args.banner_timeout),
                            do_http_probe=bool(args.http_probe),
                            http_timeout=float(args.http_timeout),
                            user_agent=args.user_agent,
                            svc_map=svc_map,
                            mode=args.enrich_mode,
                            concurrency=args.enrich_concurrency,
                        )
                        return HostReport(host=ip, resolved_name=ip_to_name.get(ip), open_ports=enriched, errors=[])

                    simple: List[PortFinding] = []
                    for p in open_ports:
                        pf = PortFinding(port=p, proto="tcp", state="open")
                        fill_service_defaults(pf, svc_map)
                        simple.append(pf)
                    return HostReport(host=ip, resolved_name=ip_to_name.get(ip), open_ports=simple, errors=[])

                ok, res, err = await run_with_timeout(per_host_task(), float(args.max_host_seconds), f"host {ip}")
                if ok and isinstance(res, HostReport):
                    hosts_reports.append(res)
                else:
                    errors.append(err or "unknown error")
                    hosts_reports.append(HostReport(host=ip, resolved_name=ip_to_name.get(ip), open_ports=[], errors=errors))

        await asyncio.gather(*[asyncio.create_task(scan_one_host(ip)) for ip in ips])
        hosts_reports.sort(key=lambda h: h.host)
        return hosts_reports

    ok_total, hosts_reports, err_total = await run_with_timeout(do_scan(), float(args.max_total_seconds), "total run")
    if not ok_total:
        finished = now_iso()
        report = ScanReport(
            target_domain=args.domain,
            nameservers_used=ns_used if ns_used else ns_ips,
            nameserver_success=ns_success,
            axfr_success=True,
            discovered_names=names,
            discovered_ips=ips,
            ports_profile=args.port_profile,
            ports_count=len(ports),
            hosts=[],
            started_at=started,
            finished_at=finished,
        )
        write_json(f"{args.out}.json", report)
        write_csv(f"{args.out}.csv", report)
        print(f"[!] {err_total}")
        print(f"[+] Report written: {args.out}.json and {args.out}.csv")
        return

    finished = now_iso()
    report = ScanReport(
        target_domain=args.domain,
        nameservers_used=ns_used if ns_used else ns_ips,
        nameserver_success=ns_success,
        axfr_success=True,
        discovered_names=names,
        discovered_ips=ips,
        ports_profile=args.port_profile,
        ports_count=len(ports),
        hosts=hosts_reports or [],
        started_at=started,
        finished_at=finished,
    )

    json_path = f"{args.out}.json"
    csv_path = f"{args.out}.csv"
    write_json(json_path, report)
    write_csv(csv_path, report)

    print(f"[+] NS IPs tried: {len(ns_ips)}")
    print(f"[+] AXFR success: True (NS: {ns_success})")
    print(f"[+] Names discovered: {len(names)} | Unique IPs resolved: {len(ips)}")
    print(f"[+] Ports profile: {args.port_profile} | Ports count: {len(ports)}")
    print(f"[+] Hosts scanned: {len(report.hosts)}")
    print(f"[+] Report written: {json_path} and {csv_path}")

    if args.html:
        written, index_path = write_html_reports(args.out, args.html_dir, report)
        abs_index = os.path.abspath(index_path)
        file_url = "file://" + quote(abs_index)
        print(f"[+] HTML written: {len(written)} files in ./{args.html_dir}")
        print(f"[+] Open report: {file_url}")

    if args.summary:
        print_summary(report)


if __name__ == "__main__":
    asyncio.run(main())
