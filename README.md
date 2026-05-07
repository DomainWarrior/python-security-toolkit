# python-security-toolkit

A lightweight Python CLI for network reconnaissance and web security auditing — built for penetration testers, security researchers, and CTF players.

> **Disclaimer:** Only use against systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Features

- **Port Scanner** — threaded TCP scanner with service detection across 40+ common services
- **Banner Grabbing** — probe open ports for service version strings
- **DNS Enumeration** — A/AAAA record resolution + reverse DNS lookups
- **HTTP Security Header Audit** — checks for HSTS, CSP, X-Frame-Options, and 7 other critical headers, with a pass/fail score

---

## Installation

```bash
git clone https://github.com/DomainWarrior/python-security-toolkit.git
cd python-security-toolkit
pip install -r requirements.txt
```

## Usage

### Port scan
```bash
# Scan common ports (1–1024)
python main.py scan example.com

# Scan a custom range with banner grabbing
python main.py scan 192.168.1.1 -p 1-65535 -b -v

# Scan a single port
python main.py scan 10.0.0.1 -p 22
```

### DNS enumeration
```bash
python main.py dns example.com
```

### Security header audit
```bash
python main.py audit https://example.com
```

---

## Example output

```
[*] Scanning 192.168.1.1  ports 1-1024 ...

────────────────────────────────────────────────────────
  Target  : 192.168.1.1  (192.168.1.1)
  Ports   : 1024 scanned in 4.32s
  Open    : 4
────────────────────────────────────────────────────────
  PORT       STATE    SERVICE            BANNER
  ─────── ─────── ───────────────── ──────────────────────────────
  22/tcp   open     SSH
  80/tcp   open     HTTP
  443/tcp  open     HTTPS
  8080/tcp open     HTTP-Alt
```

---

## Author

**MissQuibble** · [missquibble.com](https://missquibble.com) · [GitHub](https://github.com/DomainWarrior)
