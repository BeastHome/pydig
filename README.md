# pydig

## Overview
A dig-like DNS inspection tool for quick domain checks. Queries A, AAAA, NS, SOA, MX, TXT, SPF, DMARC, and CAA records with colorized output. Includes WHOIS (default) and RDAP (`--rdap`) support.

## Status
- Lifecycle: incubating
- Primary language: Python 3
- Platforms: Windows / Linux

## Usage
```
python src/pydig.py <domain> [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--ns <IP>` | Use a specific resolver instead of the system default |
| `-t, --timeout <sec>` | DNS timeout in seconds (default: 5.0) |
| `--ipv6` | Include AAAA record queries |
| `--no-whois` | Skip the WHOIS lookup |
| `--rdap` | Query RDAP instead of WHOIS |

**Examples:**
```
python src/pydig.py example.com
python src/pydig.py example.com --ns 1.1.1.1 --no-whois
python src/pydig.py example.com --rdap
```

## Dependencies
```
pip install -r requirements.txt
```
Requires: `dnspython`, `tldextract`, `python-whois`, `colorama`

## Notes
- Logs to `pydig.log` in the working directory.
- PTR lookups are attempted for A records on MX hosts (best-effort, 2s timeout).
- If a subdomain is passed (e.g. `mail.example.com`), the tool resolves both the subdomain IP and the parent domain records.