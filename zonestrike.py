#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneStrike v1.5.0 — AXFR Discovery + TCP Port Scan + Reporting + Stealth Features
Autor: Sniper (ou seu nome/handle)
Legal: Use SOMENTE com autorização explícita.
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


VERSION = "1.5.0"

BANNER = r"""
███████╗ ██████╗ ███╗   ██╗███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
███████╗╚██████╔╝██║ ╚████║███████╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

ZoneStrike v1.5.0 — AXFR + Port Scan + Stealth (UA Rotation + Proxychains)
Use SOMENTE com autorização explícita.
"""

# ──────────────────── Modelos de Dados ────────────────────
@dataclass
class PortFinding:
    port: int
    proto: str  # "tcp"
    state: str  # "open"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os_hint: Optional[str] = None
    confidence: Optional[str] = None
    evidence: Optional[str] = None
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


# ──────────────────── Constantes ────────────────────
DEFAULT_NMAP_SERVICES_PATHS = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]

LIKELY_WEB_PORTS_PLAIN = {80, 8080, 8000, 8888, 3000, 10000}
LIKELY_WEB_PORTS_TLS   = {443, 8443, 9443}

# Lista grande de User-Agents reais (atualizados 2025/2026) - para rotação
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 OPR/117.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
]


# ──────────────────── Funções utilitárias (mantidas iguais) ────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_decode(b: bytes, limit: int = 700) -> str:
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
            a, b = map(int, p.split("-", 1))
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
        if m:
            svc = m.group(1).strip()
            port = int(m.group(2))
            proto = m.group(3)
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
        if m:
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


def select_ports(profile: str, custom: str, ports_file: str, nmap_path: Optional[str]) -> List[int]:
    if profile in ("top100", "top1000"):
        if not nmap_path:
            raise FileNotFoundError("nmap-services não encontrado. Instale nmap ou use --nmap-services-path.")
        return top_ports_from_nmap_services(100 if profile == "top100" else 1000, nmap_path)
    if profile == "all":
        return list(range(1, 65536))
    if profile == "custom":
        if not custom:
            raise ValueError("--ports é obrigatório quando --port-profile=custom")
        return parse_ports(custom)
    if profile == "file":
        if not ports_file:
            raise ValueError("--ports-file é obrigatório quando --port-profile=file")
        ports = load_ports_from_file(ports_file)
        if not ports:
            raise ValueError("Arquivo de portas vazio ou inválido.")
        return ports
    raise ValueError("Perfil de portas inválido")


# ──────────────────── Descoberta de NS e AXFR ────────────────────
def discover_authoritative_ns_ips(domain: str, timeout: float = 3.0) -> List[str]:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
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


# ──────────────────── Scan de portas abertas ────────────────────
async def try_connect(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def scan_open_ports(host: str, ports: List[int], concurrency: int, timeout: float) -> List[int]:
    sem = asyncio.Semaphore(concurrency)
    open_ports: List[int] = []

    async def one(p: int) -> None:
        async with sem:
            if await try_connect(host, p, timeout):
                open_ports.append(p)

    await asyncio.gather(*[asyncio.create_task(one(p)) for p in ports])
    open_ports.sort()
    return open_ports


# ──────────────────── Identificação por banner ────────────────────
def identify_from_banner(banner: str) -> Dict[str, Optional[str]]:
    b = banner or ""
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

    if b.startswith("220 "):
        m = re.search(r"220\s+([A-Za-z0-9._-]+)\s+([0-9][0-9A-Za-z.]+)", b)
        if m:
            return dict(service_name="ftp", product=m.group(1), version=m.group(2), confidence="high", evidence="banner")
        return dict(service_name="ftp", confidence="medium", evidence="banner")

    if b.startswith("+OK"):
        return dict(service_name="pop3", confidence="medium", evidence="banner")

    if b.startswith("* OK"):
        if "Courier-IMAP" in b:
            return dict(service_name="imap", product="Courier-IMAP", confidence="high", evidence="banner")
        return dict(service_name="imap", confidence="medium", evidence="banner")

    if re.search(r"^220\s+.*(ESMTP|SMTP)", b, re.IGNORECASE):
        return dict(service_name="smtp", confidence="medium", evidence="banner")

    return {}


def fill_service_defaults(pf: PortFinding, svc_map: Dict[int, str]) -> None:
    if pf.service_name:
        return
    svc = svc_map.get(pf.port)
    if svc:
        pf.service_name = svc
        pf.confidence = pf.confidence or "low"
        pf.evidence = pf.evidence or "nmap-services"


# ──────────────────── Grab Banner ────────────────────
async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(220), timeout=0.9)
            if data:
                banner = safe_decode(data)
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
        return banner
    except Exception:
        return None


# ──────────────────── HTTP Probe com rotação de UA ────────────────────
async def http_probe(
    host: str,
    port: int,
    use_tls: bool,
    base_user_agent: str,
    rotate_ua: bool,
    timeout: float
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    try:
        ua = random.choice(USER_AGENTS) if rotate_ua else base_user_agent

        ssl_ctx = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout)

        req = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
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
            reader2, writer2 = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout)
            req2 = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
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
            await writer2.wait_closed()
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()
        return status, server, title
    except Exception:
        return None, None, None


# ──────────────────── Enriquecimento ────────────────────
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
    rotate_user_agent: bool,
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
            st, sv, title = await http_probe(host, p, tls, user_agent, rotate_user_agent, http_timeout)
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
    else:
        sem = asyncio.Semaphore(concurrency)
        async def wrapped(p: int):
            async with sem:
                await enrich_one(p)
        await asyncio.gather(*[wrapped(p) for p in open_ports])

    findings.sort(key=lambda x: x.port)
    return findings


# ──────────────────── Reporting (JSON/CSV/HTML) ────────────────────
# (as funções write_json, write_csv, compute_insights, build_host_html, build_index_html, write_html_reports
# permanecem idênticas à sua versão anterior – por brevidade não repeti aqui, mas estão no código final)

# ... insira aqui as funções de reporting que você já tinha (write_json, write_csv, compute_insights, etc.)

# ──────────────────── Main ────────────────────
async def main():
    parser = argparse.ArgumentParser(description="ZoneStrike — AXFR + Port Scanner + Stealth")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--ns", default="")
    parser.add_argument("--port-profile", choices=["top100", "top1000", "all", "custom", "file"], default="top1000")
    parser.add_argument("--ports", default="")
    parser.add_argument("--ports-file", default="")
    parser.add_argument("--nmap-services-path", default="")
    parser.add_argument("--host-concurrency", type=int, default=25)
    parser.add_argument("--port-concurrency", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=1.2)
    parser.add_argument("--enrich", action="store_true")
    parser.add_argument("--enrich-mode", choices=["serial", "parallel"], default="serial")
    parser.add_argument("--enrich-concurrency", type=int, default=20)
    parser.add_argument("--banner-timeout", type=float, default=1.8)
    parser.add_argument("--http-probe", action="store_true")
    parser.add_argument("--http-timeout", type=float, default=2.2)
    parser.add_argument("--user-agent", default=f"ZoneStrike/{VERSION} (authorized scan)")
    parser.add_argument("--rotate-user-agent", action="store_true", help="Ativa rotação automática de User-Agent")
    parser.add_argument("--use-proxychains", action="store_true", help="Tenta rodar via proxychains automaticamente")
    parser.add_argument("--out", default="zonestrike_report")
    parser.add_argument("--html", action="store_true")
    parser.add_argument("--html-dir", default="reports")
    # ... adicione os outros argumentos que você tinha (max-host-seconds, etc.)

    args = parser.parse_args()

    print(BANNER)

    # Tentativa de relançar com proxychains
    if args.use_proxychains and "proxychains" not in os.environ.get("LD_PRELOAD", ""):
        print("[*] Tentando relançar com proxychains para maior anonimato...")
        try:
            os.execvp("proxychains", ["proxychains", "-q", sys.executable] + sys.argv)
        except FileNotFoundError:
            print("[!] proxychains não encontrado. Continuando sem proxy...")
        except Exception as e:
            print(f"[!] Falha ao usar proxychains: {e}. Continuando normal...")

    # Seu fluxo principal aqui (descoberta NS, AXFR, resolve, scan, enrich, report)
    # ... cole o restante do seu main() original, ajustando apenas a chamada de enrich_open_ports para:

    # enriched = await enrich_open_ports(
    #     ...,
    #     rotate_user_agent = args.rotate_user_agent or True,   # padrão ativado
    # )

    # (o código de scan e relatório permanece o mesmo)

    print("[+] Finalizado.")


if __name__ == "__main__":
    asyncio.run(main())
