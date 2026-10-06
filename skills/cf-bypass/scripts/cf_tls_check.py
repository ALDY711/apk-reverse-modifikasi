#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS fingerprint checker for Cloudflare bypass client selection.

WHY THIS EXISTS
---------------
Cloudflare analyzes TLS Client Hello messages to fingerprint the connecting client. Each
HTTP library has a unique JA3/JA4 fingerprint based on its TLS cipher suite ordering,
supported extensions, and elliptic curves.

The `cf_clearance` cookie is cryptographically bound to the fingerprint of the browser
that solved the challenge. Using a different client (Python requests, curl, axios) to
replay the cookie will result in HTTP 403 because the fingerprint doesn't match.

This tool helps identify which clients on your system have browser-compatible fingerprints
and recommends the best client for cookie replay.

USAGE
-----
  # Check all available HTTP clients and their fingerprint compatibility
  python cf_tls_check.py --all

  # Check a specific client
  python cf_tls_check.py --client python-requests
  python cf_tls_check.py --client curl
  python cf_tls_check.py --client node-fetch

  # Test against ja3.zone fingerprint service
  python cf_tls_check.py --probe
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import ssl


# Known JA3 fingerprints and their detection status
KNOWN_FINGERPRINTS = {
    "Chrome 120+": {
        "detection": "SAFE — Cloudflare trusts this fingerprint",
        "clients": ["got-scraping", "curl_cffi (impersonate='chrome')", "puppeteer/playwright"],
        "note": "Gold standard. Use got-scraping for Node.js or curl_cffi for Python.",
    },
    "Firefox 120+": {
        "detection": "SAFE — Cloudflare trusts this fingerprint",
        "clients": ["curl_cffi (impersonate='firefox')", "puppeteer with firefox"],
        "note": "Good alternative to Chrome fingerprint.",
    },
    "Python urllib/requests": {
        "detection": "BLOCKED — Well-known bot fingerprint",
        "clients": ["urllib3", "requests", "httpx (default)"],
        "note": "Never use for cf_clearance replay. Will always get 403.",
    },
    "Node.js http/https": {
        "detection": "BLOCKED — Node.js TLS stack is distinctive",
        "clients": ["axios", "node-fetch", "undici (default)"],
        "note": "Use got-scraping instead which patches the TLS stack.",
    },
    "curl (default)": {
        "detection": "SUSPICIOUS — Often blocked on strict sites",
        "clients": ["curl"],
        "note": "curl uses OpenSSL/LibreSSL which has a distinct fingerprint.",
    },
    "Go net/http": {
        "detection": "BLOCKED — Go TLS is highly distinctive",
        "clients": ["Go stdlib http.Client"],
        "note": "Use uTLS library (github.com/refraction-networking/utls) to impersonate.",
    },
}

CLIENT_RECOMMENDATIONS = """
╔══════════════════════════════════════════════════════════════════════╗
║                RECOMMENDED CLIENTS FOR CF BYPASS                    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Node.js:                                                            ║
║    ✅ got-scraping         — Best. Chrome TLS fingerprint emulation  ║
║    ✅ puppeteer-real-browser — For challenge solving                  ║
║    ⚠️  axios/node-fetch    — WILL FAIL for cf_clearance replay      ║
║                                                                      ║
║  Python:                                                             ║
║    ✅ curl_cffi            — Chrome/Firefox JA3 impersonation        ║
║    ✅ tls-client           — Go-based TLS impersonation              ║
║    ⚠️  requests/httpx     — WILL FAIL for cf_clearance replay      ║
║    ⚠️  urllib3             — WILL FAIL for cf_clearance replay      ║
║                                                                      ║
║  CLI:                                                                ║
║    ⚠️  curl               — Sometimes works, often blocked          ║
║    ✅ curl_cffi CLI        — Chrome fingerprint via command line     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def check_python_tls():
    """Report Python's TLS/SSL configuration."""
    info = {
        "python_version": sys.version.split()[0],
        "ssl_version": ssl.OPENSSL_VERSION,
        "default_protocol": "TLSv1.2+" if hasattr(ssl, "TLSVersion") else "TLSv1.2",
        "has_tls13": hasattr(ssl, "HAS_TLSv1_3") and ssl.HAS_TLSv1_3,
    }

    # Check available cipher suites
    ctx = ssl.create_default_context()
    ciphers = ctx.get_ciphers()
    info["cipher_count"] = len(ciphers)
    info["first_5_ciphers"] = [c["name"] for c in ciphers[:5]]

    return info


def check_curl_available():
    """Check if curl is available and its TLS backend."""
    try:
        result = subprocess.run(
            ["curl", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            version_line = lines[0] if lines else "unknown"
            tls_backend = "unknown"
            for part in version_line.split():
                if any(t in part.lower() for t in ["openssl", "libressl", "boringssl", "nss", "schannel", "securetransport"]):
                    tls_backend = part
                    break
            return {
                "available": True,
                "version": version_line,
                "tls_backend": tls_backend,
                "detection_risk": "MEDIUM" if "schannel" in tls_backend.lower() else "HIGH"
            }
    except Exception:
        pass
    return {"available": False}


def check_node_available():
    """Check Node.js and key packages."""
    info = {"available": False}
    try:
        result = subprocess.run(
            ["node", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["available"] = True
            info["version"] = result.stdout.strip()

            # Check got-scraping
            check_pkg = subprocess.run(
                ["node", "-e", "try{require.resolve('got-scraping');console.log('yes')}catch{console.log('no')}"],
                capture_output=True, text=True, timeout=5
            )
            info["got_scraping_installed"] = check_pkg.stdout.strip() == "yes"
    except Exception:
        pass
    return info


def check_python_packages():
    """Check Python packages relevant for CF bypass."""
    packages = {}
    for pkg_name in ["curl_cffi", "tls_client", "requests", "httpx", "cloudscraper"]:
        try:
            __import__(pkg_name.replace("-", "_"))
            packages[pkg_name] = "INSTALLED"
        except ImportError:
            packages[pkg_name] = "NOT INSTALLED"
    return packages


def probe_fingerprint():
    """Try to identify our TLS fingerprint by connecting to a fingerprint service."""
    print("[*] Probing TLS fingerprint via tls.peet.ws/api/all...")
    try:
        req = urllib.request.Request(
            "https://tls.peet.ws/api/all",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/133.0.0.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            return {
                "ja3_hash": data.get("ja3_hash", "unknown"),
                "ja3": data.get("ja3", "unknown")[:80] + "...",
                "tls_version": data.get("tls_version", "unknown"),
                "http_version": data.get("http_version", "unknown"),
                "user_agent": data.get("user_agent", "unknown"),
                "verdict": "LIKELY BLOCKED by Cloudflare (Python urllib fingerprint)"
            }
    except Exception as e:
        return {"error": str(e), "verdict": "Could not probe fingerprint"}


def main():
    parser = argparse.ArgumentParser(
        description="TLS Fingerprint Checker for Cloudflare Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--all", action="store_true", help="Check all available clients")
    parser.add_argument("--client", help="Check specific client (curl, python-requests, node-fetch)")
    parser.add_argument("--probe", action="store_true", help="Probe actual TLS fingerprint against test service")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.all and not args.client and not args.probe:
        args.all = True

    results = {}

    if args.all or args.client:
        print("=" * 70)
        print("  TLS FINGERPRINT COMPATIBILITY CHECK FOR CLOUDFLARE BYPASS")
        print("=" * 70)

        # Python TLS info
        if args.all or args.client == "python-requests":
            python_tls = check_python_tls()
            results["python_tls"] = python_tls
            print(f"\n[Python TLS]")
            print(f"  Version     : Python {python_tls['python_version']}")
            print(f"  SSL Library : {python_tls['ssl_version']}")
            print(f"  TLS 1.3     : {'Yes' if python_tls['has_tls13'] else 'No'}")
            print(f"  Ciphers     : {python_tls['cipher_count']} available")
            print(f"  CF Verdict  : WILL BE BLOCKED (urllib/requests fingerprint is well-known)")

        # Python packages
        if args.all:
            py_packages = check_python_packages()
            results["python_packages"] = py_packages
            print(f"\n[Python Packages for CF Bypass]")
            for pkg, status in py_packages.items():
                icon = "✅" if status == "INSTALLED" else "❌"
                safe = ""
                if pkg == "curl_cffi" and status == "INSTALLED":
                    safe = " ← RECOMMENDED for CF replay"
                elif pkg in ("requests", "httpx") and status == "INSTALLED":
                    safe = " ← NOT safe for CF replay"
                print(f"  {icon} {pkg}: {status}{safe}")

        # curl
        if args.all or args.client == "curl":
            curl_info = check_curl_available()
            results["curl"] = curl_info
            print(f"\n[curl]")
            if curl_info["available"]:
                print(f"  Version     : {curl_info['version']}")
                print(f"  TLS Backend : {curl_info['tls_backend']}")
                print(f"  Risk Level  : {curl_info['detection_risk']}")
            else:
                print(f"  Status      : Not installed")

        # Node.js
        if args.all or args.client == "node-fetch":
            node_info = check_node_available()
            results["nodejs"] = node_info
            print(f"\n[Node.js]")
            if node_info["available"]:
                print(f"  Version         : {node_info['version']}")
                got_status = "✅ INSTALLED" if node_info.get("got_scraping_installed") else "❌ NOT INSTALLED"
                print(f"  got-scraping    : {got_status}")
                if not node_info.get("got_scraping_installed"):
                    print(f"                    Install: npm install got-scraping")
            else:
                print(f"  Status          : Not installed")

        # Known fingerprints summary
        print("\n[Known Fingerprint Database]")
        for name, info in KNOWN_FINGERPRINTS.items():
            print(f"\n  {name}:")
            print(f"    Detection: {info['detection']}")
            print(f"    Clients  : {', '.join(info['clients'])}")
            print(f"    Note     : {info['note']}")

        print(CLIENT_RECOMMENDATIONS)

    if args.probe:
        probe_result = probe_fingerprint()
        results["probe"] = probe_result
        print("\n[TLS Fingerprint Probe Result]")
        for k, v in probe_result.items():
            print(f"  {k}: {v}")

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
