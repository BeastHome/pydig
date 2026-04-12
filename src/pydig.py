#!/usr/bin/env python3
"""
dig-like DNS inspection tool.

Original author: David M Harris
Refactored, stabilized, and colorized with Colorama: April 2026
WHOIS + RDAP support added (non-destructive)
"""

# Standard library (no pip install needed)
import sys
import argparse
import logging
import json
import urllib.request
import urllib.error

# Requires: pip install dnspython
import dns.resolver
import dns.reversename
import dns.exception

# Requires: pip install tldextract
import tldextract

# Requires: pip install python-whois
import whois

# Requires: pip install colorama
from colorama import Fore, Style, init

# ------------------------------------------------------------
# Colorama initialization
# ------------------------------------------------------------
init(autoreset=True)


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
logging.basicConfig(
    filename="pydig.log",
    format="%(asctime)s: %(levelname)s: %(message)s",
    level=logging.INFO,
)


# ------------------------------------------------------------
# WHOIS compatibility shim (stable public API only)
# ------------------------------------------------------------
try:
    from whois.exceptions import WhoisException # pyright: ignore[reportAttributeAccessIssue]
except Exception:
    class WhoisException(Exception):
        pass


# ------------------------------------------------------------
# CLI arguments
# ------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="dig-like DNS inspection tool")
    p.add_argument("domain", nargs="?", help="Domain to check (example.com)")
    p.add_argument("--ns", help="Resolver IP (default: system resolver)")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="DNS timeout")
    p.add_argument("--ipv6", action="store_true", help="Query AAAA records")
    p.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup")
    p.add_argument("--rdap", action="store_true", help="Query RDAP metadata")
    return p.parse_args()


# ------------------------------------------------------------
# Color helpers
# ------------------------------------------------------------
def header(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


def label(text):
    print(Fore.MAGENTA + text + Style.RESET_ALL)


def error(text):
    print(Fore.RED + text + Style.RESET_ALL)


def print_ip(ip):
    print(Fore.GREEN + ip + Style.RESET_ALL)


def print_host(host):
    print(Fore.CYAN + host + Style.RESET_ALL)


# ------------------------------------------------------------
# RDAP helper (additive metadata only)
# ------------------------------------------------------------
def print_rdap(domain: str):
    header("RDAP:")

    url = f"https://rdap.org/domain/{domain}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.load(resp)

        print("Handle:", data.get("handle"))
        print("LDH Name:", data.get("ldhName"))

        for e in data.get("events", []):
            action = e.get("eventAction")
            date = e.get("eventDate")
            if action and date:
                print(f"{action}: {date}")

        for ent in data.get("entities", []):
            roles = ", ".join(ent.get("roles", []))
            vcard = ent.get("vcardArray", [])
            if vcard:
                label(f"Entity ({roles}):")
                for item in vcard[1]:
                    if item[0] in ("fn", "email"):
                        print(f"{item[0]}: {item[3]}")

        print()

    except Exception as e:
        logging.warning("RDAP failed for %s: %s", domain, e)
        error("RDAP lookup failed.")


# ------------------------------------------------------------
# WHOIS helper (legacy, best-effort)
# ------------------------------------------------------------
def safe_whois(domain: str):
    try:
        whois.whois(domain)
    except WhoisException as e:
        logging.warning("WHOIS failed for %s: %s", domain, e)
        error(f"WHOIS failed: {e}")
    except Exception:
        logging.exception("Unexpected WHOIS failure")


# ------------------------------------------------------------
# DNS helpers
# ------------------------------------------------------------
def print_ip_records(answers):
    for rdata in answers:
        print_ip(rdata.address)


def safe_ptr(ip: str, resolver: dns.resolver.Resolver) -> str:
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = resolver.nameservers
        r.timeout = r.lifetime = 2.0
        answer = r.resolve(dns.reversename.from_address(ip), "PTR")
        return str(answer[0])
    except Exception:
        return "n/a"


def resolve_dns(title: str, name: str, rdtype: str, resolver):
    print()
    header(title)
    return resolver.resolve(name, rdtype)


# ------------------------------------------------------------
# SPF / DMARC / CAA
# ------------------------------------------------------------
def summarize_spf_and_dmarc(domain: str, txt_values: list[str], resolver):
    spf = [v for v in txt_values if v.lower().startswith("v=spf1")]
    if spf:
        label("SPF:")
        for v in spf:
            print(v)

    dmarc_records = []
    try:
        for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if hasattr(r, "strings") and r.strings:
                dmarc_records.append("".join(
                    s.decode("utf-8", "replace") for s in r.strings
                ))
            else:
                dmarc_records.append(r.to_text().strip('"'))
    except Exception:
        pass

    if dmarc_records:
        label("DMARC:")
        for v in dmarc_records:
            print(v)


def print_caa(domain: str, resolver):
    label("CAA:")
    try:
        for r in resolver.resolve(domain, "CAA"):
            print(f"flag={r.flags} tag={r.tag} value={r.value}")
    except dns.resolver.NoAnswer:
        print("There are no CAA records defined.")


# ------------------------------------------------------------
# DNS record collection (UNCHANGED)
# ------------------------------------------------------------
def get_dns_records(domain: str, resolver, ipv6: bool):
    header(f"DNS for {domain}\n")

    header("A record(s):")
    try:
        print_ip_records(resolver.resolve(domain, "A"))
    except dns.resolver.NoAnswer:
        error("No A records defined.")

    if ipv6:
        header("AAAA record(s):")
        try:
            print_ip_records(resolver.resolve(domain, "AAAA"))
        except dns.resolver.NoAnswer:
            error("No AAAA records defined.")

    try:
        for r in resolve_dns("SOA:", domain, "SOA", resolver):
            print(
                f"serial={r.serial} tech={r.rname} mname={r.mname}\n"
                f"refresh={r.refresh} retry={r.retry} "
                f"expire={r.expire} minimum={r.minimum}"
            )
    except Exception:
        error("No SOA record found.")

    try:
        for ns in resolve_dns("Nameservers:", domain, "NS", resolver):
            print_host(str(ns.target))
            try:
                print_ip_records(resolver.resolve(ns.target, "A"))
            except Exception:
                pass
            print()
    except Exception:
        error("No NS records found.")

    header("MX:")
    try:
        for r in resolver.resolve(domain, "MX"):
            print(
                Fore.MAGENTA + "Host" + Style.RESET_ALL,
                Fore.CYAN + str(r.exchange) + Style.RESET_ALL,
                "preference",
                r.preference,
            )
            try:
                for ip in resolver.resolve(r.exchange, "A"):
                    print(
                        Fore.GREEN + ip.address + Style.RESET_ALL,
                        Fore.MAGENTA + "PTR:" + Style.RESET_ALL,
                        Fore.CYAN + safe_ptr(ip.address, resolver) + Style.RESET_ALL,
                    )
            except Exception:
                pass
            print()
    except dns.resolver.NoAnswer:
        error("There are no MX records defined.")

    header("TXT:")
    txt_values = []

    try:
        for r in resolver.resolve(domain, "TXT"):
            if hasattr(r, "strings") and r.strings:
                value = "".join(s.decode("utf-8", "replace") for s in r.strings)
            else:
                value = r.to_text().strip('"')
            txt_values.append(value)

        for v in txt_values:
            print(v)

    except dns.resolver.NoAnswer:
        print("There are no TXT records defined.")

    summarize_spf_and_dmarc(domain, txt_values, resolver)
    print_caa(domain, resolver)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main(domain_name, clean_domain_name, resolver, args) -> int:
    if args.rdap:
        print_rdap(domain_name)
    elif not args.no_whois:
        safe_whois(domain_name)

    try:
        resolver.resolve(domain_name, "SOA")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print(
            Fore.YELLOW
            + f"Domain {domain_name} does not resolve in DNS."
            + Style.RESET_ALL
        )
        return 2

    if clean_domain_name != domain_name:
        print(f"{clean_domain_name} is a subdomain of {domain_name}\n")
        try:
            print_ip_records(resolver.resolve(clean_domain_name, "A"))
        except Exception:
            error("No A records for subdomain.")
        print()

    get_dns_records(domain_name, resolver, args.ipv6)
    return 0


# ------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()

    entered = args.domain or input("Enter the domain to check: ").strip()
    extracted = tldextract.extract(entered)

    clean_domain_name = extracted.fqdn.rstrip(".")
    domain_name = extracted.top_domain_under_public_suffix

    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver.lifetime = args.timeout

    if args.ns:
        resolver.nameservers = [args.ns]

    sys.exit(main(domain_name, clean_domain_name, resolver, args))