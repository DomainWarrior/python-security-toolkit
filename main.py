#!/usr/bin/env python3
"""
python-security-toolkit
A lightweight network reconnaissance & security auditing tool.

Usage:
  python main.py scan   <target> [options]
  python main.py dns    <domain>
  python main.py audit  <url>
  python main.py help
"""

import argparse
import sys

from scanner import scan, print_results
from osint   import resolve_dns, print_header_audit
from utils   import color, validate_ip, parse_ports


BANNER = r"""
  ____  ____  ____ _____ __  __   _____           _ _    _ _
 |  _ \/ ___||  _ \_   _|  \/  | |_   _|__   ___ | | | _(_) |_
 | |_) \___ \| | | || | | |\/| |   | |/ _ \ / _ \| | |/ / | __|
 |  __/ ___) | |_| || | | |  | |   | | (_) | (_) | |   <| | |_
 |_|   |____/|____/ |_| |_|  |_|   |_|\___/ \___/|_|_|\_\_|\__|

  python-security-toolkit  |  github.com/DomainWarrior
  Use responsibly. Only scan systems you own or have permission to test.
"""


def cmd_scan(args) -> None:
    if not validate_ip(args.target):
        print(color("red") + f"Invalid target: {args.target}" + color("reset"))
        sys.exit(1)

    lo, hi = parse_ports(args.ports)
    if lo < 1 or hi > 65535 or lo > hi:
        print(color("red") + "Port range must be between 1-65535." + color("reset"))
        sys.exit(1)

    print(color("cyan") + f"\n[*] Scanning {args.target}  ports {lo}-{hi} ..." + color("reset"))
    try:
        data = scan(args.target, (lo, hi), grab_banners=args.banners)
        print_results(data, verbose=args.verbose)
    except ValueError as e:
        print(color("red") + str(e) + color("reset"))
        sys.exit(1)


def cmd_dns(args) -> None:
    bld = color("bold")
    grn = color("green")
    cyn = color("cyan")
    rst = color("reset")

    print(f"\n{bld}DNS Enumeration — {args.domain}{rst}")
    print("─" * 50)

    data = resolve_dns(args.domain)
    if "error" in data:
        print(color("red") + f"Error: {data['error']}" + rst)
        sys.exit(1)

    for ip in data["ipv4"]:
        rev = data["reverse"].get(ip, "")
        print(f"  {grn}A   {rst} {ip:<20}  {cyn}{rev}{rst}")
    for ip in data["ipv6"]:
        rev = data["reverse"].get(ip, "")
        print(f"  {grn}AAAA{rst} {ip:<40}  {cyn}{rev}{rst}")
    print()


def cmd_audit(args) -> None:
    print_header_audit(args.url)


def main() -> None:
    print(color("green") + BANNER + color("reset"))

    parser = argparse.ArgumentParser(
        prog="security-toolkit",
        description="Lightweight network recon & security audit toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── scan ────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan open ports on a target")
    p_scan.add_argument("target",             help="IP address or hostname")
    p_scan.add_argument("-p", "--ports",      default="common",
                        help="Port range: '80', '1-1024', 'common', 'full'  (default: common)")
    p_scan.add_argument("-b", "--banners",    action="store_true",
                        help="Attempt banner grabbing on open ports")
    p_scan.add_argument("-v", "--verbose",    action="store_true",
                        help="Show banners in output table")

    # ── dns ─────────────────────────────────────────────────
    p_dns = sub.add_parser("dns", help="DNS enumeration for a domain")
    p_dns.add_argument("domain", help="Domain to enumerate")

    # ── audit ───────────────────────────────────────────────
    p_audit = sub.add_parser("audit", help="HTTP security header audit")
    p_audit.add_argument("url", help="URL to audit (e.g. https://example.com)")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "dns":
        cmd_dns(args)
    elif args.command == "audit":
        cmd_audit(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
