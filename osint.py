"""
Lightweight OSINT helpers: DNS enumeration, WHOIS, header fingerprinting.
"""

import socket
import urllib.request
import urllib.error
import json
from utils import color


def resolve_dns(domain: str) -> dict:
    """Resolve A, AAAA, and reverse DNS for a domain."""
    results: dict = {"domain": domain, "ipv4": [], "ipv6": [], "reverse": {}}

    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            addr = info[4][0]
            if ":" in addr:
                if addr not in results["ipv6"]:
                    results["ipv6"].append(addr)
            else:
                if addr not in results["ipv4"]:
                    results["ipv4"].append(addr)
    except socket.gaierror as e:
        results["error"] = str(e)
        return results

    # Reverse lookups
    for ip in results["ipv4"] + results["ipv6"]:
        try:
            host = socket.gethostbyaddr(ip)[0]
            results["reverse"][ip] = host
        except socket.herror:
            results["reverse"][ip] = None

    return results


def http_headers(url: str) -> dict:
    """
    Fetch HTTP response headers from a URL.
    Returns a dict of header name → value.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (security-audit)"},
            method="HEAD",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return dict(resp.headers)
    except urllib.error.URLError as e:
        return {"error": str(e)}


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS enforces HTTPS",
    "Content-Security-Policy":   "CSP limits XSS attack surface",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Referrer-Policy":           "Controls referrer information leakage",
    "Permissions-Policy":        "Restricts browser feature access",
    "X-XSS-Protection":          "Legacy XSS filter (deprecated but common)",
}


def audit_headers(headers: dict) -> list[dict]:
    """
    Cross-reference response headers against a list of recommended
    security headers and return a pass/fail report.
    """
    report = []
    h_lower = {k.lower(): v for k, v in headers.items()}
    for name, description in SECURITY_HEADERS.items():
        present = name.lower() in h_lower
        report.append({
            "header":      name,
            "present":     present,
            "value":       h_lower.get(name.lower(), ""),
            "description": description,
        })
    return report


def print_header_audit(url: str) -> None:
    """Print a formatted security-header audit for a URL."""
    grn = color("green")
    red = color("red")
    yel = color("yellow")
    rst = color("reset")
    bld = color("bold")
    dim = color("dim")

    print(f"\n{bld}Security Header Audit — {url}{rst}")
    print(f"{'─'*60}")

    headers = http_headers(url)
    if "error" in headers:
        print(f"{red}Error fetching headers: {headers['error']}{rst}")
        return

    # Show server fingerprint info
    for field in ("Server", "X-Powered-By", "X-Generator"):
        if field in headers:
            print(f"  {yel}[!] {field}: {headers[field]}{rst}  ← potential info leak")

    print()
    report = audit_headers(headers)
    passed = sum(1 for r in report if r["present"])
    total  = len(report)

    for r in report:
        icon = f"{grn}✓{rst}" if r["present"] else f"{red}✗{rst}"
        val  = f"  {dim}{r['value'][:50]}{rst}" if r["present"] else ""
        print(f"  {icon}  {r['header']:<35}{val}")

    print(f"\n  Score: {passed}/{total} security headers present")
    print(f"  {'Good shape!' if passed >= 5 else 'Missing key headers — review above.'}\n")
