#!/usr/bin/env python3
"""Server-Side Request Forgery (SSRF) and Cloud Metadata Security Validator.

Validates URLs and IP addresses against private networks, loopbacks, link-local metadata
(AWS/GCP/Azure/K8s), and IP obfuscation techniques (Hex, Octal, Dword, IPv6 mapping).
Can generate copy-paste defensive safe HTTP client code for Python, PHP, and Node.js.

Usage:
    python ssrf_validator.py --url "http://169.254.169.254/latest/meta-data/"
    python ssrf_validator.py --url "http://0177.0.0.1/"
    python ssrf_validator.py --generate-safe-client python
    python ssrf_validator.py --help
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import urllib.parse


BLOCKED_NETWORKS = [
    (ipaddress.ip_network("0.0.0.0/8"), "Broadcast / Current Network"),
    (ipaddress.ip_network("10.0.0.0/8"), "RFC 1918 Private Network (Class A)"),
    (ipaddress.ip_network("100.64.0.0/10"), "Carrier-Grade NAT (RFC 6598)"),
    (ipaddress.ip_network("127.0.0.0/8"), "Loopback Address (Localhost)"),
    (ipaddress.ip_network("169.254.0.0/16"), "Link-Local / Cloud Metadata Service (AWS/GCP/Azure)"),
    (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918 Private Network (Class B)"),
    (ipaddress.ip_network("192.0.0.0/24"), "IETF Protocol Assignments"),
    (ipaddress.ip_network("192.0.2.0/24"), "TEST-NET-1 (RFC 5737)"),
    (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918 Private Network (Class C)"),
    (ipaddress.ip_network("198.18.0.0/15"), "Network Benchmark Tests (RFC 2544)"),
    (ipaddress.ip_network("198.51.100.0/24"), "TEST-NET-2 (RFC 5737)"),
    (ipaddress.ip_network("203.0.113.0/24"), "TEST-NET-3 (RFC 5737)"),
    (ipaddress.ip_network("224.0.0.0/4"), "Multicast (RFC 5771)"),
    (ipaddress.ip_network("240.0.0.0/4"), "Reserved / Future Use (RFC 1112)"),
    (ipaddress.ip_network("::1/128"), "IPv6 Loopback"),
    (ipaddress.ip_network("fc00::/7"), "IPv6 Unique Local (RFC 4193)"),
    (ipaddress.ip_network("fe80::/10"), "IPv6 Link-Local Unicast"),
]


def decode_obfuscated_ip(host_str: str) -> str:
    """Attempt to normalize obfuscated IP formats (Dword, Hex, Octal)."""
    # Clean brackets if IPv6
    raw = host_str.strip("[]")

    # 1. Check Dword integer (e.g. 2130706433 -> 127.0.0.1)
    if raw.isdigit():
        try:
            val = int(raw)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except Exception:
            pass

    # 2. Check Hex integer (e.g. 0x7f000001)
    if raw.lower().startswith("0x") and not "." in raw:
        try:
            val = int(raw, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except Exception:
            pass

    # 3. Check Dotted Octal or Dotted Hex (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    if "." in raw:
        parts = raw.split(".")
        if len(parts) <= 4:
            try:
                norm_parts = []
                for p in parts:
                    if p.lower().startswith("0x"):
                        norm_parts.append(str(int(p, 16)))
                    elif p.startswith("0") and len(p) > 1 and p.isdigit():
                        norm_parts.append(str(int(p, 8)))
                    elif p.isdigit():
                        norm_parts.append(p)
                    else:
                        break
                if len(norm_parts) == len(parts):
                    # Handle shorthand forms (e.g. 127.1 -> 127.0.0.1)
                    if len(norm_parts) == 2:
                        return f"{norm_parts[0]}.0.0.{norm_parts[1]}"
                    elif len(norm_parts) == 3:
                        return f"{norm_parts[0]}.{norm_parts[1]}.0.{norm_parts[2]}"
                    elif len(norm_parts) == 4:
                        return ".".join(norm_parts)
            except Exception:
                pass

    return host_str


def check_ip_security(ip_str: str) -> tuple[bool, str]:
    """Check if an IP address belongs to blocked networks."""
    try:
        ip = ipaddress.ip_address(ip_str)

        # Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        for net, desc in BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Blocked Range: {net} ({desc})"

        return True, "Safe Public IP"
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"


def validate_url(url: str) -> dict:
    """Perform comprehensive SSRF analysis on a given URL."""
    report = {
        "url": url,
        "is_safe": True,
        "risk_level": "LOW",
        "findings": [],
        "resolved_ips": []
    }

    parsed = urllib.parse.urlparse(url)

    # 1. Scheme check
    if not parsed.scheme:
        report["is_safe"] = False
        report["risk_level"] = "HIGH"
        report["findings"].append("Missing URL scheme.")
        return report

    if parsed.scheme.lower() not in ("http", "https"):
        report["is_safe"] = False
        report["risk_level"] = "CRITICAL"
        report["findings"].append(f"Dangerous/Unsafe scheme detected: {parsed.scheme} (Allowed: http, https)")

    hostname = parsed.hostname
    if not hostname:
        report["is_safe"] = False
        report["risk_level"] = "HIGH"
        report["findings"].append("Missing hostname.")
        return report

    # 2. Check for Cloud Metadata keywords
    cloud_keywords = ["169.254.169.254", "metadata.google.internal", "metadata.nic", "instance-data"]
    for kw in cloud_keywords:
        if kw in hostname.lower():
            report["is_safe"] = False
            report["risk_level"] = "CRITICAL"
            report["findings"].append(f"Target explicitly names Cloud Metadata service ({kw})")

    # 3. Check for IP normalization & obfuscation
    normalized_host = decode_obfuscated_ip(hostname)
    if normalized_host != hostname:
        report["findings"].append(f"Obfuscated IP detected: {hostname} resolves to {normalized_host}")

    # Check direct IP
    direct_safe, direct_msg = check_ip_security(normalized_host)
    if not direct_safe and "Invalid IP" not in direct_msg:
        report["is_safe"] = False
        report["risk_level"] = "CRITICAL"
        report["findings"].append(f"Host points directly to forbidden address: {normalized_host} - {direct_msg}")
        return report

    # 4. Resolve DNS
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        resolved = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set([sock[4][0] for sock in resolved]))
        report["resolved_ips"] = ips

        for ip in ips:
            safe, msg = check_ip_security(ip)
            if not safe:
                report["is_safe"] = False
                report["risk_level"] = "CRITICAL"
                report["findings"].append(f"DNS Resolution points to forbidden IP: {ip} ({msg})")
    except socket.gaierror as e:
        report["findings"].append(f"DNS resolution failed: {e}")

    if report["is_safe"] and not report["findings"]:
        report["findings"].append("All resolved IPs are public and routeable. No SSRF indicators detected.")

    return report


def generate_defensive_client(lang: str) -> str:
    """Generate safe HTTP client code snippet."""
    if lang == "python":
        return '''# Defensive Anti-SSRF HTTP Client (Python)
import ipaddress
import socket
import urllib.parse
import requests

BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def safe_request(url: str, timeout: int = 5):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid scheme. Only HTTP and HTTPS allowed.")
    
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Pre-flight DNS check (anti-SSRF)
    resolved = socket.getaddrinfo(parsed.hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for res in resolved:
        ip = ipaddress.ip_address(res[4][0])
        if any(ip in net for net in BLOCKED_NETS):
            raise PermissionError(f"Access Denied: Private/Metadata IP {ip}")
    
    # Do not follow redirects automatically to prevent redirect chains
    return requests.get(url, allow_redirects=False, timeout=timeout)
'''
    elif lang == "php":
        return '''// Defensive Anti-SSRF URL Validator (PHP)
function isSafeUrl(string $url): bool {
    $parts = parse_url($url);
    if (!isset($parts['scheme']) || !in_array($parts['scheme'], ['http', 'https'], true)) {
        return false;
    }
    $host = $parts['host'] ?? '';
    if (empty($host)) return false;

    $records = dns_get_record($host, DNS_A + DNS_AAAA);
    if (empty($records)) return false;

    foreach ($records as $record) {
        $ip = $record['ip'] ?? $record['ipv6'] ?? '';
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false; // Pointing to private / reserved network
        }
    }
    return true;
}
'''
    else:  # Node.js
        return '''// Defensive Anti-SSRF URL Fetcher (Node.js)
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function isSafeUrl(targetUrl) {
    const url = new URL(targetUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return false;
    }
    const lookups = await dns.lookup(url.hostname, { all: true });
    for (const entry of lookups) {
        const addr = ipaddr.parse(entry.address);
        const range = addr.range();
        if (['loopback', 'private', 'linkLocal', 'carrierGradeNat'].includes(range)) {
            return false;
        }
    }
    return true;
}
'''


def main():
    parser = argparse.ArgumentParser(
        description="SSRF & Cloud Metadata Security Validator."
    )
    parser.add_argument("--url", type=str, help="Target URL to inspect for SSRF vulnerabilities")
    parser.add_argument("--ip", type=str, help="Target IP address to check against private/metadata CIDRs")
    parser.add_argument("--generate-safe-client", choices=["python", "php", "nodejs"],
                        help="Generate defensive anti-SSRF HTTP client code template")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if args.generate_safe_client:
        print(generate_defensive_client(args.generate_safe_client))
        return

    if args.ip:
        norm = decode_obfuscated_ip(args.ip)
        safe, msg = check_ip_security(norm)
        res = {"ip": args.ip, "normalized": norm, "is_safe": safe, "details": msg}
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            status = "[✓] SAFE" if safe else "[!] BLOCKED"
            print(f"{status} - IP: {args.ip} (Normalized: {norm}) -> {msg}")
        return

    if args.url:
        report = validate_url(args.url)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("=" * 70)
            print(" SSRF & CLOUD METADATA AUDIT REPORT")
            print(f" URL: {report['url']}")
            print(f" Status: {'[✓] SAFE' if report['is_safe'] else '[!] VULNERABLE'}")
            print(f" Risk Level: {report['risk_level']}")
            if report["resolved_ips"]:
                print(f" Resolved IPs: {', '.join(report['resolved_ips'])}")
            print(" Findings:")
            for f in report["findings"]:
                print(f"  - {f}")
            print("=" * 70)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
