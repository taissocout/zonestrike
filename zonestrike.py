#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneStrike — AXFR Discovery + TCP Port Scan + Reporting

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
    nameservers_used: List[str]          # IPs that were tried
    nameserver_success: Optional[str]    # IP that succeeded AXFR (if any)
    axfr_success: bool
    discovered_names: List[str]
    discovered_ips: List[str]
    ports_profile: str
    ports_count: int
    hosts: List[HostReport]
    started_at: str
    finished_at: str
    version: str = "1.1.0"


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
        raise FileNotFoundError(f"nmap-services não encontrado em {custom_path}")

    for p in DEFAULT_NMAP_SERVICES_PATHS:
        if Path(p).exists():
            return p
    raise FileNotFoundError("nmap-services não encontrado. Instale nmap ou informe --nmap-services-path")

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
            raise ValueError("Use --ports quando --port-profile=custom")
        return parse_ports(custom)
    if profile == "file":
        if not ports_file:
            raise ValueError("Use --ports-file quando --port-profile=file")
        ports = load_ports_from_file(ports_file)
        if not ports:
            raise ValueError("Arquivo de portas vazio ou inválido.")
        return ports
    raise ValueError("Perfil de portas inválido")


# -------------------- NS Discovery (AUTO) --------------------
def discover_authoritative_ns_ips(domain: str, timeout: float = 3.0) -> List[str]:
    """
    Discovers NS names for the domain and resolves them to A/AAAA.
    Returns list of IPs (unique, ordered).
    """
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
        # A
        try:
            a = r.resolve(ns, "A")
            ips.extend([rr.to_text() for rr in a])
        except Exception:
            pass
        # AAAA
        try:
            aaaa = r.resolve(ns, "AAAA")
            ips.extend([rr.to_text() for rr in aaaa])
        except Exception:
            pass

    return uniq_keep_order([ip for ip in ips if ip])


# -------------------- AXFR --------------------
def do_axfr(domain: str, nameserver_ip: str, timeout: float = 6.0) -> Tuple[bool, List[str], str]:
    """
    Returns (success, fqdn_names, error_message)
    """
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
    """
    Resolve A records using a specific nameserver (by IP).
    Returns mapping name -> list of IPs.
    """
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


# -------------------- Reporting --------------------
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


# -------------------- Main --------------------
async def main() -> None:
    ap = argparse.ArgumentParser(description="ZoneStrike — AXFR + TCP Port Scanner (authorized testing only).")

    ap.add_argument("--domain", required=True, help="Domain/zone (e.g. example.com)")

    # ns is now optional
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

    # Optional HTTP probe
    ap.add_argument("--http-probe", action="store_true", help="Simple HTTP probe on open web ports (80/443/8080/8443...).")
    ap.add_argument("--user-agent", default="ZoneStrike/1.1.0 (authorized testing)",
                    help="Fixed User-Agent used ONLY for HTTP probe (not used in TCP port scan).")
    ap.add_argument("--http-timeout", type=float, default=2.0, help="HTTP probe timeout seconds")

    ap.add_argument("--out", default="zonestrike_report", help="Output base name (writes .json and .csv)")
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
        # No NS IPs discovered -> report empty
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
        write_json(f"{args.out}.json", report)
        write_csv(f"{args.out}.csv", report)
        print("[!] Could not discover any authoritative NS IPs. Check DNS or pass --ns explicitly.")
        print(f"[+] Report written: {args.out}.json and {args.out}.csv")
        return

    # 1) AXFR: try each NS IP until success
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
        write_json(f"{args.out}.json", report)
        write_csv(f"{args.out}.csv", report)
        print("[!] AXFR failed on all discovered/provided NS IPs.")
        # mostra só uma amostra de erros para debug sem poluir
        for e in axfr_errors[:3]:
            print(f"    - {e}")
        print(f"[+] Report written: {args.out}.json and {args.out}.csv")
        return

    # 2) Resolve A records using the NS that succeeded AXFR
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

    # 3) Ports selection
    nmap_path = args.nmap_services_path.strip() or None
    ports = select_ports(args.port_profile, args.ports, args.ports_file, nmap_path)

    # 4) Scan (parallel by host)
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


if __name__ == "__main__":
    asyncio.run(main())
