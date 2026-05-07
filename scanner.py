"""
Port scanner with threading, banner grabbing, and service detection.
"""

import socket
import threading
from queue import Queue
from datetime import datetime
from utils import color, SERVICES


THREAD_COUNT = 100
TIMEOUT = 1.0
_lock = threading.Lock()


def grab_banner(ip: str, port: int) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(1024).decode(errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        return ""


def probe_port(ip: str, port: int, results: list, grab: bool) -> None:
    """Check a single port and record results."""
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            service = SERVICES.get(port, "unknown")
            banner  = grab_banner(ip, port) if grab else ""
            with _lock:
                results.append({
                    "port":    port,
                    "state":   "open",
                    "service": service,
                    "banner":  banner,
                })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass


def scan(target: str, port_range: tuple[int, int], grab_banners: bool = False) -> dict:
    """
    Scan a target host across a port range.

    Returns a dict with host info and a list of open ports.
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {target}")

    results: list = []
    queue:   Queue = Queue()
    start = datetime.now()

    for p in range(port_range[0], port_range[1] + 1):
        queue.put(p)

    def worker():
        while not queue.empty():
            port = queue.get()
            probe_port(ip, port, results, grab_banners)
            queue.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(THREAD_COUNT)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    results.sort(key=lambda r: r["port"])

    elapsed = (datetime.now() - start).total_seconds()
    return {
        "target":   target,
        "ip":       ip,
        "elapsed":  elapsed,
        "scanned":  port_range[1] - port_range[0] + 1,
        "open":     results,
    }


def print_results(data: dict, verbose: bool = False) -> None:
    """Pretty-print scan results to stdout."""
    hdr = color("bold")
    rst = color("reset")
    grn = color("green")
    yel = color("yellow")
    cyn = color("cyan")
    red = color("red")

    print(f"\n{hdr}{'─'*56}{rst}")
    print(f"  {hdr}Target  :{rst} {data['target']}  ({data['ip']})")
    print(f"  {hdr}Ports   :{rst} {data['scanned']} scanned in {data['elapsed']:.2f}s")
    print(f"  {hdr}Open    :{rst} {grn}{len(data['open'])}{rst}")
    print(f"{hdr}{'─'*56}{rst}")

    if not data["open"]:
        print(f"  {red}No open ports found.{rst}\n")
        return

    print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<18} {'BANNER'}")
    print(f"  {'─'*7} {'─'*7} {'─'*17} {'─'*30}")
    for r in data["open"]:
        port_str = f"{cyn}{r['port']}/tcp{rst}"
        state_str = f"{grn}open{rst}"
        svc_str   = f"{yel}{r['service']:<18}{rst}"
        banner    = r["banner"][:40] if verbose and r["banner"] else ""
        print(f"  {port_str:<20} {state_str:<20} {svc_str} {banner}")
    print()
