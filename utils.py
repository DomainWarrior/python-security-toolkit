"""
Shared utilities: ANSI colours, common service names, IP validation.
"""

import re
import sys

# ANSI colour codes (disabled on Windows without colorama)
_CODES = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "dim":    "\033[2m",
}

def color(name: str) -> str:
    """Return an ANSI escape code, or empty string if stdout is not a TTY."""
    if not sys.stdout.isatty():
        return ""
    return _CODES.get(name, "")


# Well-known port → service name mapping
SERVICES: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "Syslog",
    587:  "SMTP/TLS",
    631:  "IPP",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "Zookeeper",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    6667: "IRC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017:"MongoDB",
}


def validate_ip(host: str) -> bool:
    """Basic sanity check — accepts hostnames and IPv4 addresses."""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # Accept hostnames
    return bool(re.match(r"^[a-zA-Z0-9._-]+$", host))


def parse_ports(spec: str) -> tuple[int, int]:
    """
    Parse a port specification string into a (start, end) tuple.

    Accepts:
      '80'         → (80, 80)
      '1-1024'     → (1, 1024)
      'common'     → (1, 1024)
      'full'       → (1, 65535)
    """
    spec = spec.strip().lower()
    if spec == "common":
        return (1, 1024)
    if spec == "full":
        return (1, 65535)
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return (int(lo), int(hi))
    p = int(spec)
    return (p, p)
