#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneStrike — AXFR Discovery + TCP Port Scan + Reporting (JSON/CSV/HTML)

Author: (coloque seu nome/handle aqui)
Credits:
- dnspython (DNS / AXFR)
- Python asyncio (concurrency)

Legal: Use ONLY with explicit authorization.
"""

import argparse
import asyncio
import csv
import json
import random
import re
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import dns.query
import dns.resolver
import dns.zone


BANNER = r"""
███████╗ ██████╗ ███╗   ██╗███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
███████╗╚██████╔╝██║ ╚████║███████╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

ZoneStrike — AXFR Discovery + TCP Port Scan + Reporting
Use ONLY with explicit authorization.
"""


# -------------------- Data Models --------------------
@dataclass
class PortFinding:
    port: int
    proto: str  # "tcp"
    state: str  # "open"
    service_guess: Optional[str] = None
    banner: Optional[str] = None
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None


@dataclass
class HostReport:
    host: str  # IP
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
    version: str = "1.2.0"


# -------------------- Constants --------------------
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds (smb)",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

DEFAULT_NMAP_SERVICES_PATHS = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]


# -------------------- Utils --------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_decode(b: bytes, limit: int = 400) -> str:
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

def find_nmap_services_file(custom_path: Optional[str] = None) -> str:
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return str(p)
        raise FileNotFoundError(f"nmap-services not found at {custom_path}")

    for p in DEFAULT_NMAP_SERVICES_PATHS:
        if Path(p).exists():
            return p
    raise FileNotFoundError("nmap-services not found. Install nmap or use --nmap-services-path")

def top_ports_from_nmap_services(n: int, proto: str = "tcp", path: Optional[str] = None) -> List[int]:
    services_path = find_nmap_services_file(path)
    text = Path(services_path).read_text(encoding="utf-8", errors="ignore")

    rx = re.compile(r"^\s*([^\s]+)\s+(\d+)\/(tcp|udp)\s+([0-9.]+)")
    rows: List[Tuple[float, int]] = []

    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if not m:
            continue
        port = int(m.group(2))
        pproto = m.group(3)
        freq = float(m.group(4))
        if pproto == proto and 1 <= port <= 65535:
            rows.append((freq, port))

    rows.sort(reverse=True, key=lambda x: x[0])

    out: List[int] = []
    seen: Set[int] = set()
    for _, port in rows:
        if port not in seen:
            seen.add(port)
            out.append(port)
        if len(out) >= n:
            break
    return out

def select_ports(profile: str, custom: str, ports_file: str, nmap_services_path: Optional[str]) -> List[int]:
    if profile == "top100":
        return top_ports_from_nmap_services(100, "tcp", nmap_services_path)
    if profile == "top1000":
        return top_ports_from_nmap_services(1000, "tcp", nmap_services_path)
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


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

def safe_filename(s: str) -> str:
    # keep letters/numbers/.-_ ; replace other chars with underscore
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)


# -------------------- NS Discovery (AUTO) --------------------
def discover_authoritative_ns_ips(domain: str, timeout: float = 3.0) -> List[str]:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout

    ns_names: List[str] = []
    try:
        ans = r.resolve(domain, "NS")
        ns_names = [rr.to_text().rstrip(".") for rr in ans]
    except Exception:
        return []

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

    return uniq_keep_order([ip for ip in ips if ip])


# -------------------- AXFR --------------------
def do_axfr(domain: str, nameserver_ip: str, timeout: float = 6.0) -> Tuple[bool, List[str], str]:
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

def resolve_names_to_ips(names: List[str], resolver_nameserver_ip: str, timeout: float = 3.0) -> Dict[str, List[str]]:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_nameserver_ip]
    r.timeout = timeout
    r.lifetime = timeout

    out: Dict[str, List[str]] = {}
    for n in names:
        try:
            ans = r.resolve(n, "A")
            out[n] = [a.to_text() for a in ans]
        except Exception:
            out[n] = []
    return out


# -------------------- TCP Scan --------------------
async def try_connect(host: str, port: int, timeout: float) -> Tuple[str, Optional[str]]:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        banner = None
        try:
            data = await asyncio.wait_for(reader.read(160), timeout=0.8)
            if data:
                banner = safe_decode(data)
        except Exception:
            banner = None

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return "open", banner
    except Exception:
        return "closed", None

async def scan_host_ports(host: str, ports: List[int], concurrency: int, timeout: float) -> List[PortFinding]:
    sem = asyncio.Semaphore(concurrency)
    findings: List[PortFinding] = []

    async def one(port: int) -> None:
        async with sem:
            state, banner = await try_connect(host, port, timeout)
            if state == "open":
                findings.append(
                    PortFinding(
                        port=port,
                        proto="tcp",
                        state="open",
                        service_guess=COMMON_SERVICES.get(port),
                        banner=banner,
                    )
                )

    tasks = [asyncio.create_task(one(p)) for p in ports]
    await asyncio.gather(*tasks)
    findings.sort(key=lambda f: f.port)
    return findings


# -------------------- Optional HTTP Probe (UA FIXO) --------------------
async def http_probe(host: str, port: int, use_tls: bool, user_agent: str, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    try:
        ssl_ctx = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=timeout,
        )

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
        try:
            reader2, writer2 = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=timeout,
            )
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

            writer2.close()
            try:
                await writer2.wait_closed()
            except Exception:
                pass

            html_text = html.decode("utf-8", errors="replace")
            mt = re.search(r"(?is)<title>\s*(.*?)\s*</title>", html_text)
            if mt:
                title = re.sub(r"\s+", " ", mt.group(1).strip())[:120]
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
            "service_guess", "banner",
            "http_status", "http_server", "http_title"
        ])
        for hr in report.hosts:
            for pf in hr.open_ports:
                w.writerow([
                    hr.host,
                    hr.resolved_name or "",
                    pf.port,
                    pf.proto,
                    pf.state,
                    pf.service_guess or "",
                    pf.banner or "",
                    pf.http_status if pf.http_status is not None else "",
                    pf.http_server or "",
                    pf.http_title or "",
                ])


# -------------------- Reporting (HTML) --------------------
def build_host_html(report: ScanReport, host: HostReport) -> str:
    host_id = host.resolved_name or host.host
    title = f"ZoneStrike Report — {report.target_domain} — {host_id}"

    # Ports table rows (banner shown as last column)
    rows = []
    for pf in host.open_ports:
        banner = pf.banner or ""
        # keep banners at the end (as requested)
        rows.append(
            "<tr>"
            f"<td>{pf.port}</td>"
            f"<td>{html_escape(pf.proto)}</td>"
            f"<td>{html_escape(pf.state)}</td>"
            f"<td>{html_escape(pf.service_guess or '')}</td>"
            f"<td>{html_escape(str(pf.http_status) if pf.http_status is not None else '')}</td>"
            f"<td>{html_escape(pf.http_server or '')}</td>"
            f"<td>{html_escape(pf.http_title or '')}</td>"
            f"<td><code>{html_escape(banner)}</code></td>"
            "</tr>"
        )

    errors_html = ""
    if host.errors:
        items = "".join(f"<li><code>{html_escape(e)}</code></li>" for e in host.errors)
        errors_html = f"<h3>Errors</h3><ul>{items}</ul>"

    summary_ports = ", ".join(str(p.port) for p in host.open_ports) if host.open_ports else "None"

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html_escape(title)}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 24px; }}
  .meta {{ color: #333; margin-bottom: 16px; }}
  .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 16px 0; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border-bottom: 1px solid #eee; text-align: left; padding: 8px; vertical-align: top; }}
  th {{ background: #fafafa; }}
  code {{ white-space: pre-wrap; word-break: break-word; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:999px; background:#f2f2f2; margin-left:8px; font-size: 12px; }}
  .small {{ font-size: 12px; color: #555; }}
</style>
</head>
<body>
  <h1>ZoneStrike Host Report</h1>
  <div class="meta">
    <div><strong>Target:</strong> {html_escape(report.target_domain)}</div>
    <div><strong>Host:</strong> {html_escape(host.host)} {f"<span class='pill'>{html_escape(host.resolved_name)}</span>" if host.resolved_name else ""}</div>
    <div class="small"><strong>Started:</strong> {html_escape(report.started_at)} | <strong>Finished:</strong> {html_escape(report.finished_at)} | <strong>Version:</strong> {html_escape(report.version)}</div>
    <div class="small"><strong>AXFR:</strong> {html_escape(str(report.axfr_success))} | <strong>NS success:</strong> {html_escape(report.nameserver_success or "None")}</div>
    <div class="small"><strong>Open ports:</strong> {html_escape(summary_ports)}</div>
  </div>

  <div class="card">
    <h2>Open Ports</h2>
    <table>
      <thead>
        <tr>
          <th>Port</th>
          <th>Proto</th>
          <th>State</th>
          <th>Service</th>
          <th>HTTP</th>
          <th>Server</th>
          <th>Title</th>
          <th>Banner (last)</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows) if rows else '<tr><td colspan="8">No open ports found.</td></tr>'}
      </tbody>
    </table>
  </div>

  {errors_html}

  <hr/>
  <div class="small">
    <strong>Credits:</strong> dnspython, Python asyncio<br/>
    <strong>Legal:</strong> Use ONLY with explicit authorization.
  </div>
</body>
</html>"""
    return html

def build_index_html(report: ScanReport, host_files: List[Tuple[str, HostReport]]) -> str:
    title = f"ZoneStrike Report Index — {report.target_domain}"
    rows = []
    for filename, hr in host_files:
        host_label = hr.resolved_name or hr.host
        open_ports = ", ".join(str(p.port) for p in hr.open_ports) if hr.open_ports else "None"
        rows.append(
            "<tr>"
            f"<td><a href='{html_escape(filename)}'>{html_escape(host_label)}</a></td>"
            f"<td>{html_escape(hr.host)}</td>"
            f"<td>{html_escape(open_ports)}</td>"
            f"<td>{len(hr.open_ports)}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html_escape(title)}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 24px; }}
  .meta {{ color: #333; margin-bottom: 16px; }}
  .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 16px 0; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border-bottom: 1px solid #eee; text-align: left; padding: 8px; vertical-align: top; }}
  th {{ background: #fafafa; }}
  .small {{ font-size: 12px; color: #555; }}
</style>
</head>
<body>
  <h1>ZoneStrike Report Index</h1>
  <div class="meta">
    <div><strong>Target:</strong> {html_escape(report.target_domain)}</div>
    <div class="small"><strong>Started:</strong> {html_escape(report.started_at)} | <strong>Finished:</strong> {html_escape(report.finished_at)} | <strong>Version:</strong> {html_escape(report.version)}</div>
    <div class="small"><strong>AXFR:</strong> {html_escape(str(report.axfr_success))} | <strong>NS success:</strong> {html_escape(report.nameserver_success or "None")}</div>
    <div class="small"><strong>Discovered:</strong> {len(report.discovered_names)} names | {len(report.discovered_ips)} IPs</div>
  </div>

  <div class="card">
    <h2>Hosts</h2>
    <table>
      <thead>
        <tr>
          <th>Host (name)</th>
          <th>IP</th>
          <th>Open ports</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows) if rows else '<tr><td colspan="4">No hosts.</td></tr>'}
      </tbody>
    </table>
  </div>

  <hr/>
  <div class="small">
    <strong>Credits:</strong> dnspython, Python asyncio<br/>
    <strong>Legal:</strong> Use ONLY with explicit authorization.
  </div>
</body>
</html>"""
    return html

def write_html_reports(out_base: str, report: ScanReport) -> List[str]:
    """
    Writes:
      - {out_base}_index.html
      - {out_base}_{host}.html  (host = resolved_name if available else ip)
    Returns list of written filenames.
    """
    written: List[str] = []

    host_files: List[Tuple[str, HostReport]] = []
    for hr in report.hosts:
        host_id = hr.resolved_name or hr.host
        fname = f"{out_base}_{safe_filename(host_id)}.html"
        html = build_host_html(report, hr)
        Path(fname).write_text(html, encoding="utf-8")
        written.append(fname)
        host_files.append((fname, hr))

    index_name = f"{out_base}_index.html"
    index_html = build_index_html(report, host_files)
    Path(index_name).write_text(index_html, encoding="utf-8")
    written.append(index_name)

    return written


# -------------------- Main --------------------
async def main() -> None:
    ap = argparse.ArgumentParser(description="ZoneStrike — AXFR + TCP Port Scanner (authorized testing only).")

    ap.add_argument("--domain", required=True, help="Domain/zone (e.g. example.com)")
    ap.add_argument("--ns", default="", help="Authoritative nameserver IP. If omitted, ZoneStrike auto-discovers NS IPs.")

    ap.add_argument("--port-profile", choices=["top100", "top1000", "all", "custom", "file"], default="top1000",
                    help="Ports profile: top100/top1000/all/custom/file")
    ap.add_argument("--ports", default="", help="Used with custom. Example: 1-1024,3306,8080")
    ap.add_argument("--ports-file", default="", help="Used with file. One port per line or CSV.")
    ap.add_argument("--nmap-services-path", default="", help="Path to nmap-services (optional).")

    ap.add_argument("--host-concurrency", type=int, default=30, help="Hosts in parallel")
    ap.add_argument("--port-concurrency", type=int, default=300, help="Ports per host in parallel")
    ap.add_argument("--timeout", type=float, default=1.2, help="TCP connect timeout seconds")

    ap.add_argument("--delay", type=float, default=0.0, help="Delay (sec) before scanning each host (reduces load).")
    ap.add_argument("--jitter", type=float, default=0.0, help="Random jitter (sec) added to delay (reduces spikes).")

    ap.add_argument("--axfr-timeout", type=float, default=6.0, help="AXFR timeout seconds")
    ap.add_argument("--dns-timeout", type=float, default=3.0, help="DNS resolve timeout seconds")

    ap.add_argument("--http-probe", action="store_true", help="Simple HTTP probe on open web ports (80/443/8080/8443...).")
    ap.add_argument("--user-agent", default="ZoneStrike/1.2.0 (authorized testing)",
                    help="Fixed User-Agent used ONLY for HTTP probe (not used in TCP port scan).")
    ap.add_argument("--http-timeout", type=float, default=2.0, help="HTTP probe timeout seconds")

    ap.add_argument("--out", default="zonestrike_report", help="Output base name (writes .json/.csv and optional HTML)")
    ap.add_argument("--html", action="store_true", help="Generate HTML reports (per-host + index).")
    ap.add_argument("--no-banner", action="store_true", help="Do not print banner")

    args = ap.parse_args()

    if not args.no_banner:
        print(BANNER)

    started = now_iso()

    # Determine NS IPs to try
    ns_ips: List[str] = []
    if args.ns.strip():
        ns_ips = [args.ns.strip()]
    else:
        ns_ips = discover_authoritative_ns_ips(args.domain, timeout=args.dns_timeout)

    ns_ips = uniq_keep_order(ns_ips)

    if not ns_ips:
        finished = now_iso()
        report = ScanReport(
            target_domain=args.domain,
            nameservers_used=[],
            nameserver_success=None,
            axfr_success=False,
            discovered_names=[],
            discovered_ips=[],
            ports_profile=args.port_profile,
            ports_count=0,
            hosts=[],
            started_at=started,
            finished_at=finished,
        )
        json_path = f"{args.out}.json"
        csv_path = f"{args.out}.csv"
        write_json(json_path, report)
        write_csv(csv_path, report)
        print("[!] Could not discover any authoritative NS IPs. Check DNS or pass --ns explicitly.")
        print(f"[+] Report written: {json_path} and {csv_path}")
        return

    # AXFR try each NS
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

    if not axfr_ok:
        finished = now_iso()
        report = ScanReport(
            target_domain=args.domain,
            nameservers_used=ns_ips,
            nameserver_success=None,
            axfr_success=False,
            discovered_names=[],
            discovered_ips=[],
            ports_profile=args.port_profile,
            ports_count=0,
            hosts=[],
            started_at=started,
            finished_at=finished,
        )
        json_path = f"{args.out}.json"
        csv_path = f"{args.out}.csv"
        write_json(json_path, report)
        write_csv(csv_path, report)
        print("[!] AXFR failed on all discovered/provided NS IPs.")
        for e in axfr_errors[:3]:
            print(f"    - {e}")
        print(f"[+] Report written: {json_path} and {csv_path}")
        return

    # Resolve A records using NS that succeeded
    name_to_ips = resolve_names_to_ips(names, ns_success, timeout=float(args.dns_timeout))

    ips: List[str] = []
    for iplist in name_to_ips.values():
        ips.extend(iplist)
    ips = uniq_keep_order([ip for ip in ips if ip])

    ip_to_name: Dict[str, str] = {}
    for n, iplist in name_to_ips.items():
        for ip in iplist:
            if ip and ip not in ip_to_name:
                ip_to_name[ip] = n

    # Ports selection
    nmap_path = args.nmap_services_path.strip() or None
    ports = select_ports(args.port_profile, args.ports, args.ports_file, nmap_path)

    # Scan
    hosts_reports: List[HostReport] = []
    host_sem = asyncio.Semaphore(args.host_concurrency)

    async def scan_one_host(ip: str) -> None:
        async with host_sem:
            errors: List[str] = []
            if args.delay > 0 or args.jitter > 0:
                await asyncio.sleep(max(0.0, args.delay) + (random.random() * max(0.0, args.jitter)))

            try:
                open_ports = await scan_host_ports(
                    ip,
                    ports=ports,
                    concurrency=args.port_concurrency,
                    timeout=float(args.timeout),
                )

                if args.http_probe and open_ports:
                    web_candidates: List[Tuple[PortFinding, bool]] = []
                    for pf in open_ports:
                        if pf.port in (80, 8080, 8000, 8888, 3000):
                            web_candidates.append((pf, False))
                        elif pf.port in (443, 8443, 9443):
                            web_candidates.append((pf, True))

                    probe_sem = asyncio.Semaphore(10)

                    async def probe_one(pf: PortFinding, tls: bool) -> None:
                        async with probe_sem:
                            st, sv, title = await http_probe(ip, pf.port, tls, args.user_agent, float(args.http_timeout))
                            pf.http_status = st
                            pf.http_server = sv
                            pf.http_title = title

                    await asyncio.gather(*[
                        asyncio.create_task(probe_one(pf, tls)) for pf, tls in web_candidates
                    ])

                hosts_reports.append(
                    HostReport(
                        host=ip,
                        resolved_name=ip_to_name.get(ip),
                        open_ports=open_ports,
                        errors=errors,
                    )
                )

            except Exception as e:
                errors.append(f"scan_error: {e}")
                hosts_reports.append(
                    HostReport(
                        host=ip,
                        resolved_name=ip_to_name.get(ip),
                        open_ports=[],
                        errors=errors,
                    )
                )

    await asyncio.gather(*[asyncio.create_task(scan_one_host(ip)) for ip in ips])

    finished = now_iso()
    hosts_reports.sort(key=lambda h: h.host)

    report = ScanReport(
        target_domain=args.domain,
        nameservers_used=ns_ips,
        nameserver_success=ns_success,
        axfr_success=True,
        discovered_names=names,
        discovered_ips=ips,
        ports_profile=args.port_profile,
        ports_count=len(ports),
        hosts=hosts_reports,
        started_at=started,
        finished_at=finished,
    )

    json_path = f"{args.out}.json"
    csv_path = f"{args.out}.csv"
    write_json(json_path, report)
    write_csv(csv_path, report)

    print(f"[+] NS IPs tried: {len(ns_ips)}")
    print(f"[+] AXFR success: True (NS: {ns_success})")
    print(f"[+] Names discovered: {len(names)} | IPs resolved: {len(ips)}")
    print(f"[+] Ports profile: {args.port_profile} | Ports count: {len(ports)}")
    print(f"[+] Hosts scanned: {len(hosts_reports)}")
    print(f"[+] Report written: {json_path} and {csv_path}")

    if args.html:
        written = write_html_reports(args.out, report)
        # print only the most useful names
        print(f"[+] HTML written: {len(written)} files (index: {args.out}_index.html)")


if __name__ == "__main__":
    asyncio.run(main())
