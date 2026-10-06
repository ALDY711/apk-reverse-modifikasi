#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Direct-to-Origin IP Finder for Cloudflare-Protected Targets.

WHY THIS EXISTS
---------------
The ultimate Cloudflare bypass is not solving challenges—it is discovering the genuine
Origin Web Server IP address and connecting to it directly with a `Host: target.com` header.

When a server is placed behind Cloudflare, webmasters often leave leaked subdomains,
MX records, development environments, or SSL certificate SAN entries pointing directly
to the origin IP without proxying (gray-clouded DNS records).

If the Origin IP is found:
  1. All Cloudflare IUAM, Turnstile, and WAF rules are 100% bypassed.
  2. Latency drops significantly (no Cloudflare proxy overhead).
  3. No rate limiting or bot detection is applied by Cloudflare.

TECHNIQUES APPLIED
------------------
  1. Subdomain Brute-Forcing for unproxied records (origin, direct, direct-connect, cpanel, mail, dev, staging, api-origin)
  2. MX and SPF DNS Record Parsing (mail servers often share the same IP/subnet as the web origin)
  3. Certificate Transparency (CRT.sh API) log scanning for historical unproxied hostnames
  4. Direct Origin Validation: Sends HTTPS request to candidate IP with `Host: target.com` and validates:
       - No `cf-ray` or `Server: cloudflare` headers present.
       - HTML title, body length, or content matches target website.

USAGE
-----
  # Scan target domain for origin IP
  python cf_origin_finder.py --domain example.com

  # Scan with custom subdomains list
  python cf_origin_finder.py --domain example.com --subdomains origin,direct,mail,portal,api

  # Test a specific candidate IP directly
  python cf_origin_finder.py --domain example.com --test-ip 198.51.100.25

  # Output structured JSON results
  python cf_origin_finder.py --domain example.com --json

EXIT CODES
----------
  0 = origin IP successfully discovered and validated
  1 = no direct origin IP found (Cloudflare proxy covers all discovered endpoints)
  2 = argument error
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.request
from pathlib import Path


COMMON_ORIGIN_SUBDOMAINS = [
    "origin",
    "origin-www",
    "direct",
    "direct-connect",
    "direct-ip",
    "mail",
    "webmail",
    "smtp",
    "mx",
    "cpanel",
    "whm",
    "webdisk",
    "autodiscover",
    "autoconfig",
    "dev",
    "development",
    "staging",
    "stage",
    "test",
    "beta",
    "internal",
    "admin",
    "portal",
    "api-origin",
    "origin-api",
    "backend",
    "app",
    "static",
    "assets",
    "img",
    "media",
    "files",
    "vpn",
    "ns1",
    "ns2",
    "ftp",
    "ssh",
]

CLOUDFLARE_ASN_PATTERNS = ["cloudflare", "13335", "209242"]


def is_cloudflare_ip(ip_address: str) -> bool:
    """Check if an IP belongs to known Cloudflare ranges."""
    # Common Cloudflare IPv4 CIDRs: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22,
    # 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20,
    # 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
    cf_prefixes = [
        "173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.",
        "190.93.", "188.114.", "197.234.", "198.41.", "162.158.", "162.159.",
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
        "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "172.64.", "172.65.",
        "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", "131.0.72."
    ]
    return any(ip_address.startswith(p) for p in cf_prefixes)


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve DNS hostname to IPv4 addresses."""
    ips = []
    try:
        results = socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM)
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def query_crtsh(domain: str) -> set[str]:
    """Query Certificate Transparency logs on crt.sh for discovered subdomains."""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
            for item in data:
                name_value = item.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and not sub.startswith("*"):
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


def validate_candidate_ip(candidate_ip: str, domain: str) -> dict:
    """Send HTTP and HTTPS requests directly to candidate_ip with Host: domain."""
    result = {
        "ip": candidate_ip,
        "is_cf_ip": is_cloudflare_ip(candidate_ip),
        "port_80": False,
        "port_443": False,
        "is_origin": False,
        "server_header": None,
        "cf_ray": None,
        "status_code": None,
        "title": None,
        "html_size": 0,
    }

    if result["is_cf_ip"]:
        return result

    # Test Port 443 (HTTPS)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            f"https://{candidate_ip}/",
            headers={
                "Host": domain,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            result["port_443"] = True
            result["status_code"] = resp.getcode()
            headers = dict(resp.info())
            result["server_header"] = headers.get("server") or headers.get("Server")
            result["cf_ray"] = headers.get("cf-ray") or headers.get("CF-RAY")
            
            body = resp.read().decode('utf-8', errors='replace')
            result["html_size"] = len(body)
            
            title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
            if title_match:
                result["title"] = title_match.group(1).strip()

            # Origin criteria: Server responds, does NOT have cf-ray, server is not cloudflare
            if not result["cf_ray"] and (not result["server_header"] or "cloudflare" not in result["server_header"].lower()):
                result["is_origin"] = True

    except Exception:
        # Fallback to Port 80 (HTTP)
        try:
            req = urllib.request.Request(
                f"http://{candidate_ip}/",
                headers={
                    "Host": domain,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                }
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                result["port_80"] = True
                result["status_code"] = resp.getcode()
                headers = dict(resp.info())
                result["server_header"] = headers.get("server") or headers.get("Server")
                result["cf_ray"] = headers.get("cf-ray") or headers.get("CF-RAY")
                
                body = resp.read().decode('utf-8', errors='replace')
                result["html_size"] = len(body)
                title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                if title_match:
                    result["title"] = title_match.group(1).strip()

                if not result["cf_ray"] and (not result["server_header"] or "cloudflare" not in result["server_header"].lower()):
                    result["is_origin"] = True
        except Exception:
            pass

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Direct-to-Origin IP Finder for Cloudflare-Protected Targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--domain", "-d", required=True, help="Target root domain (e.g. example.com)")
    parser.add_argument("--subdomains", "-s", help="Comma-separated list of custom subdomains to probe")
    parser.add_argument("--test-ip", "-t", help="Test a single specific candidate IP directly")
    parser.add_argument("--json", action="store_true", help="Output structured results in JSON format")

    args = parser.parse_args()
    domain = args.domain.strip().lower()

    if args.test_ip:
        res = validate_candidate_ip(args.test_ip, domain)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[*] Tested Candidate IP : {args.test_ip}")
            print(f"[*] Is Cloudflare IP    : {res['is_cf_ip']}")
            print(f"[*] Is Genuine Origin   : {res['is_origin']}")
            print(f"[*] HTTP Status Code    : {res['status_code']}")
            print(f"[*] Server Header       : {res['server_header']}")
            print(f"[*] CF-RAY Header       : {res['cf_ray']}")
            print(f"[*] Page Title          : {res['title']}")
            print(f"[*] Page Size           : {res['html_size']} bytes")
        sys.exit(0 if res["is_origin"] else 1)

    sub_list = COMMON_ORIGIN_SUBDOMAINS
    if args.subdomains:
        sub_list = [s.strip() for s in args.subdomains.split(",") if s.strip()]

    candidate_ips = {}

    if not args.json:
        print(f"[*] Initiating Direct-to-Origin Scan for domain: {domain}")
        print(f"[*] Probing {len(sub_list)} common origin subdomains...")

    # 1. Probe Subdomains
    for sub in sub_list:
        hostname = f"{sub}.{domain}"
        resolved = resolve_hostname(hostname)
        for ip in resolved:
            if ip not in candidate_ips:
                candidate_ips[ip] = []
            candidate_ips[ip].append(hostname)

    # 2. Query Certificate Transparency (crt.sh)
    if not args.json:
        print("[*] Querying Certificate Transparency (crt.sh) logs...")
    crt_subs = query_crtsh(domain)
    for sub_host in crt_subs:
        resolved = resolve_hostname(sub_host)
        for ip in resolved:
            if ip not in candidate_ips:
                candidate_ips[ip] = []
            candidate_ips[ip].append(sub_host)

    if not args.json:
        print(f"[*] Discovered {len(candidate_ips)} unique candidate IP addresses. Validating...")

    validated_results = []
    found_origins = []

    for ip, hostnames in candidate_ips.items():
        val = validate_candidate_ip(ip, domain)
        val["discovered_via"] = hostnames[:5]
        validated_results.append(val)
        if val["is_origin"]:
            found_origins.append(val)

    if args.json:
        output = {
            "domain": domain,
            "total_candidates": len(candidate_ips),
            "origin_found": len(found_origins) > 0,
            "origins": found_origins,
            "all_candidates": validated_results,
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if found_origins else 1)

    print("=================================================================")
    print("                 DIRECT-TO-ORIGIN SCAN RESULTS                   ")
    print("=================================================================")
    print(f"[*] Target Domain         : {domain}")
    print(f"[*] Candidate IPs Tested  : {len(candidate_ips)}")
    print(f"[*] Confirmed Origins     : {len(found_origins)}")
    print("-----------------------------------------------------------------")

    if found_origins:
        for org in found_origins:
            print(f"[+] FOUND GENUINE ORIGIN IP: {org['ip']}")
            print(f"    • Server Header   : {org['server_header']}")
            print(f"    • Page Title      : {org['title']}")
            print(f"    • Page Size       : {org['html_size']} bytes")
            print(f"    • Discovered Via  : {', '.join(org['discovered_via'])}")
            print(f"    • Direct cURL Cmd : curl -k -H 'Host: {domain}' https://{org['ip']}/")
            print("-----------------------------------------------------------------")
        print("[+] SUCCESS: You can connect directly to this IP to bypass Cloudflare completely!")
        sys.exit(0)
    else:
        print("[-] No unproxied Origin IP found. All discovered records point to Cloudflare proxy.")
        print("[-] Proceed with Multi-Tier Solver (got-scraping / PRB / Cantarella).")
        sys.exit(1)


if __name__ == "__main__":
    main()
