"""
Network Security Scanner - Backend Engine
Handles port scanning, service detection, and vulnerability hints.
"""

import socket
import threading
from datetime import datetime
from typing import Optional

# Try importing nmap AND verify the binary exists
try:
    import nmap
    _test = nmap.PortScanner()   # raises EnvironmentError if nmap binary missing
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False


# Common service port mappings
PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Submit", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-Server", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4000: "Dev-Server", 4443: "HTTPS-Alt",
    5000: "Flask/Dev", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    6443: "Kubernetes", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM", 9200: "Elasticsearch",
    9300: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB",
}

# Vulnerability hints by port
VULNERABILITY_HINTS = {
    21: "⚠️ FTP transmits credentials in plaintext. Use SFTP instead.",
    22: "ℹ️ SSH exposed. Ensure key-based auth and disable root login.",
    23: "🔴 Telnet is unencrypted and highly insecure. Disable immediately.",
    25: "⚠️ SMTP open relay risk. Verify relay restrictions.",
    53: "ℹ️ DNS open resolver may enable amplification attacks.",
    80: "ℹ️ HTTP is unencrypted. Consider redirecting to HTTPS.",
    135: "⚠️ MSRPC exposure. Common target for worm propagation.",
    139: "⚠️ NetBIOS can leak system info. Disable if not needed.",
    443: "✅ HTTPS - verify TLS version (TLS 1.2+ recommended).",
    445: "🔴 SMB exposed. High-risk (EternalBlue/WannaCry vector).",
    1433: "⚠️ MSSQL exposed publicly. Restrict to internal networks.",
    3306: "⚠️ MySQL exposed publicly. Restrict to localhost/VPN.",
    3389: "🔴 RDP exposed. High brute-force risk. Enable NLA and restrict IP.",
    5432: "⚠️ PostgreSQL exposed. Restrict to localhost or VPN.",
    5900: "🔴 VNC exposed. Often weak/no auth. Tunnel through SSH.",
    6379: "🔴 Redis exposed without auth by default. Restrict access immediately.",
    8080: "ℹ️ HTTP proxy/dev server exposed. Verify intentional exposure.",
    27017: "🔴 MongoDB default has no auth. Secure immediately if exposed.",
    9200: "⚠️ Elasticsearch API exposed. May leak sensitive data.",
}


def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def get_service_name(port: int) -> str:
    """Get service name for a port number."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def tcp_connect_scan(host: str, ports: list, timeout: float = 1.0) -> list:
    """
    Multithreaded TCP connect scan using Python sockets only.
    No root/admin required. Works on all platforms without nmap.
    """
    results = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            status = "open" if result == 0 else "closed"
            with lock:
                results.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": status,
                    "service": get_service_name(port),
                    "vulnerability": VULNERABILITY_HINTS.get(port, ""),
                })
        except Exception:
            with lock:
                results.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": get_service_name(port),
                    "vulnerability": "",
                })

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1)

    return sorted(results, key=lambda x: x["port"])


def nmap_scan(host: str, scan_type: str, port_range: str = "1-1024", timeout: float = 1.0) -> list:
    """
    Run nmap scan if available, otherwise silently fall back to
    the pure-Python TCP connect scanner. Never raises an exception.
    """
    ports = parse_port_range(port_range)

    # No nmap binary on this system → use Python fallback
    if not NMAP_AVAILABLE:
        return tcp_connect_scan(host, ports, timeout=timeout)

    try:
        nm = nmap.PortScanner()
        args_map = {
            "tcp_syn":       f"-sS -p {port_range}",
            "tcp_connect":   f"-sT -p {port_range}",
            "udp":           f"-sU -p {port_range}",
            "comprehensive": f"-sS -sV -p {port_range}",
        }
        args = args_map.get(scan_type, f"-sT -p {port_range}")
        nm.scan(host, arguments=args)

        # If nmap returned no hosts, fall back
        if host not in nm.all_hosts():
            return tcp_connect_scan(host, ports, timeout=timeout)

        results = []
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info     = nm[host][proto][port]
                service  = info.get("name", get_service_name(port))
                product  = info.get("product", "")
                version  = info.get("version", "")
                svc_full = f"{service} {product} {version}".strip()
                results.append({
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state", "unknown"),
                    "service": svc_full or get_service_name(port),
                    "vulnerability": VULNERABILITY_HINTS.get(port, ""),
                })
        return results

    except Exception:
        # Any error (binary missing, permission denied, etc.) → Python fallback
        return tcp_connect_scan(host, ports, timeout=timeout)


def parse_port_range(port_range: str) -> list:
    """Parse port range string like '1-1024' or '80,443,8080' into list."""
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports[:500]   # Cap at 500 ports for safety


def get_open_ports(results: list) -> list:
    return [r for r in results if r["state"] == "open"]


def get_scan_summary(results: list, host: str, scan_type: str, duration: float) -> dict:
    open_ports  = get_open_ports(results)
    risky_ports = [r for r in open_ports if r.get("vulnerability", "").startswith(("🔴", "⚠️"))]
    return {
        "host": host,
        "scan_type": scan_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": round(duration, 2),
        "total_scanned": len(results),
        "open_count": len(open_ports),
        "closed_count": len(results) - len(open_ports),
        "risky_count": len(risky_ports),
        "nmap_available": NMAP_AVAILABLE,
    }
