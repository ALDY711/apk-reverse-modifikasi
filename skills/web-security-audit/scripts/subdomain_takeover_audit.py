#!/usr/bin/env python3
"""Audit DNS records for Dangling CNAMEs and potential Subdomain Takeover vulnerabilities.

Matches CNAME targets against known SaaS/Cloud provider fingerprints (AWS S3, GitHub Pages,
Heroku, Azure, Cloudflare, Zendesk, Fastly, Shopify, Pantheon, etc.) and inspects live HTTP responses.

Usage:
    python subdomain_takeover_audit.py --domain docs.example.com
    python subdomain_takeover_audit.py --file subdomains.txt --json
    python subdomain_takeover_audit.py --help
"""

import argparse
import json
import socket
import sys
import urllib.request
import urllib.error


TAKEOVER_FINGERPRINTS = [
    {
        "service": "AWS S3 Bucket",
        "cname_pattern": ["s3.amazonaws.com", "s3-website"],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
            "404 Not Found"
        ],
        "severity": "HIGH"
    },
    {
        "service": "GitHub Pages",
        "cname_pattern": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file"
        ],
        "severity": "HIGH"
    },
    {
        "service": "Heroku",
        "cname_pattern": ["herokuapp.com"],
        "fingerprints": [
            "No such app",
            "Heroku | No such app",
            "<title>No such app</title>"
        ],
        "severity": "HIGH"
    },
    {
        "service": "Microsoft Azure",
        "cname_pattern": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "fingerprints": [
            "404 Web Site not found.",
            "Web Site not found",
            "The resource you are looking for has been removed"
        ],
        "severity": "HIGH"
    },
    {
        "service": "Zendesk",
        "cname_pattern": ["zendesk.com"],
        "fingerprints": [
            "Help Center Closed",
            "this help center no longer exists"
        ],
        "severity": "MEDIUM"
    },
    {
        "service": "Fastly CDN",
        "cname_pattern": ["fastly.net"],
        "fingerprints": [
            "Fastly error: unknown domain:"
        ],
        "severity": "HIGH"
    },
    {
        "service": "Shopify",
        "cname_pattern": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable."
        ],
        "severity": "HIGH"
    },
    {
        "service": "Pantheon",
        "cname_pattern": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek."
        ],
        "severity": "MEDIUM"
    },
    {
        "service": "Cloudflare",
        "cname_pattern": ["cdn.cloudflare.net"],
        "fingerprints": [
            "Error 1016: Origin DNS error",
            "Origin DNS error"
        ],
        "severity": "MEDIUM"
    }
]


def resolve_cname(domain: str) -> list[str]:
    """Attempt basic CNAME resolution using socket."""
    cnames = []
    try:
        # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        canonical, aliases, _ = socket.gethostbyname_ex(domain)
        if canonical != domain:
            cnames.append(canonical)
        for a in aliases:
            if a != domain and a not in cnames:
                cnames.append(a)
    except Exception:
        pass
    return cnames


def probe_http(domain: str, timeout: int = 5) -> tuple[int, str]:
    """Perform a benign GET request to check HTTP response body."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecurityAudit/1.0",
        "Accept": "*/*"
    }
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read().decode("utf-8", errors="ignore")
                return res.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            continue
    return 0, ""


def audit_domain(domain: str, timeout: int = 5) -> dict:
    """Audit single domain for takeover vulnerability."""
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    elif clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    clean_domain = clean_domain.split("/")[0]

    report = {
        "domain": clean_domain,
        "cnames": resolve_cname(clean_domain),
        "is_vulnerable": False,
        "matched_service": None,
        "severity": "SAFE",
        "evidence": None
    }

    # Match CNAME against cloud providers
    matched_provider = None
    for target in report["cnames"]:
        for prov in TAKEOVER_FINGERPRINTS:
            if any(pattern in target.lower() for pattern in prov["cname_pattern"]):
                matched_provider = prov
                break
        if matched_provider:
            break

    # If matched or probe is requested, inspect HTTP body
    status_code, body = probe_http(clean_domain, timeout=timeout)
    if not body:
        return report

    # Check fingerprints
    candidates = [matched_provider] if matched_provider else TAKEOVER_FINGERPRINTS
    for prov in candidates:
        if not prov:
            continue
        for fp in prov["fingerprints"]:
            if fp.lower() in body.lower():
                report["is_vulnerable"] = True
                report["matched_service"] = prov["service"]
                report["severity"] = prov["severity"]
                report["evidence"] = f"HTTP {status_code} response contains fingerprint: '{fp}'"
                return report

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Audit DNS and HTTP responses for Dangling CNAMEs and Subdomain Takeover."
    )
    parser.add_argument("--domain", "-d", type=str, help="Single domain to audit")
    parser.add_argument("--file", "-f", type=str, help="Text file containing list of domains to audit")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP request timeout in seconds (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                domains = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except Exception as e:
            sys.exit(f"[-] Error reading domains file: {e}")
    else:
        parser.print_help()
        sys.exit(1)

    reports = []
    for d in domains:
        reports.append(audit_domain(d, timeout=args.timeout))

    if args.json:
        print(json.dumps(reports, indent=2))
        return

    print("=" * 75)
    print(" SUBDOMAIN TAKEOVER & DANGLING CNAME AUDIT")
    print("=" * 75)

    vulnerable_count = 0
    for r in reports:
        if r["is_vulnerable"]:
            vulnerable_count += 1
            print(f"[!] VULNERABLE: {r['domain']}")
            print(f"    Service:  {r['matched_service']} (Severity: {r['severity']})")
            if r["cnames"]:
                print(f"    CNAMEs:   {', '.join(r['cnames'])}")
            print(f"    Evidence: {r['evidence']}")
        else:
            cname_str = f" -> {', '.join(r['cnames'])}" if r["cnames"] else ""
            print(f"[✓] SAFE: {r['domain']}{cname_str}")

    print("=" * 75)
    print(f"Audit completed: {len(reports)} domain(s) checked. {vulnerable_count} vulnerable.")


if __name__ == "__main__":
    main()
