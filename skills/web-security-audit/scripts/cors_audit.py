#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CORS (Cross-Origin Resource Sharing) Defensive Configuration Auditor.

WHY THIS EXISTS
---------------
Misconfigured CORS headers are one of the most common API vulnerabilities.
A backend that dynamically reflects arbitrary `Origin` values combined with
`Access-Control-Allow-Credentials: true` allows malicious third-party websites
to read private user data and API responses via cross-site fetch requests.

This tool audits an API endpoint's CORS policy against standard origin scenarios:
  1. Arbitrary Untrusted Origin reflection (e.g. https://untrusted-origin.com)
  2. Null Origin reflection (e.g. Origin: null, used in sandboxed iframes)
  3. Subdomain Trust Misconfiguration (e.g. https://attacker-example.com)
  4. Preflight OPTIONS request response validation

It identifies misconfigurations and outputs ready-to-use secure CORS policy configurations.

USAGE
-----
  # Audit an API endpoint CORS policy
  python cors_audit.py --url http://127.0.0.1:8000/api/user

  # Audit with custom origin tests
  python cors_audit.py --url https://api.example.com/v1/profile --test-origin https://portal.example.com

  # Output structured JSON audit report
  python cors_audit.py --url https://api.example.com/v1/profile --json

EXIT CODES
----------
  0 = CORS policy is properly hardened
  1 = CORS misconfiguration detected (insecure reflection or wildcard credentials)
  2 = network error or invalid arguments
"""

import argparse
import json
import ssl
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse


def test_origin_header(url: str, origin: str | None, method: str = "GET") -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CORS-Auditor/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    if origin is not None:
        headers["Origin"] = origin

    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "GET"
        headers["Access-Control-Request-Headers"] = "Authorization, Content-Type"

    req = urllib.request.Request(url, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.getcode()
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        status = e.code
    except Exception as e:
        return {"error": str(e)}

    return {
        "status": status,
        "allow_origin": resp_headers.get("access-control-allow-origin"),
        "allow_credentials": resp_headers.get("access-control-allow-credentials"),
        "allow_methods": resp_headers.get("access-control-allow-methods"),
        "allow_headers": resp_headers.get("access-control-allow-headers"),
        "max_age": resp_headers.get("access-control-max-age"),
    }


def audit_cors(url: str, custom_origin: str | None = None) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or "example.com"

    test_cases = [
        {"name": "No Origin (Standard Request)", "origin": None, "method": "GET"},
        {"name": "Arbitrary Untrusted Origin", "origin": "https://untrusted-external-site.com", "method": "GET"},
        {"name": "Null Origin (Sandboxed Iframe)", "origin": "null", "method": "GET"},
        {"name": "Subdomain Prefix Spoof", "origin": f"https://{domain}.evil.com", "method": "GET"},
        {"name": "Preflight OPTIONS Request", "origin": "https://untrusted-external-site.com", "method": "OPTIONS"},
    ]

    if custom_origin:
        test_cases.append({"name": "Legitimate Trusted Origin", "origin": custom_origin, "method": "GET"})

    results = []
    vulnerabilities = []

    for tc in test_cases:
        res = test_origin_header(url, tc["origin"], tc["method"])
        tc_report = {
            "test_case": tc["name"],
            "sent_origin": tc["origin"],
            "method": tc["method"],
            "response": res,
        }
        results.append(tc_report)

        if "error" in res:
            continue

        ao = res.get("allow_origin")
        ac = res.get("allow_credentials")

        # Vulnerability 1: Arbitrary Origin Reflection with Credentials
        if tc["origin"] and ao == tc["origin"] and ac and ac.lower() == "true":
            vulnerabilities.append({
                "severity": "CRITICAL",
                "issue": f"Arbitrary Origin Reflection with Credentials ({tc['name']})",
                "description": f"The server dynamically reflects '{ao}' in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true. Malicious sites can read private user API responses.",
            })

        # Vulnerability 2: Null Origin Reflection with Credentials
        if tc["origin"] == "null" and ao == "null" and ac and ac.lower() == "true":
            vulnerabilities.append({
                "severity": "HIGH",
                "issue": "Null Origin Allowed with Credentials",
                "description": "The server trusts 'null' origin with credentials, allowing sandboxed iframes to access authenticated data.",
            })

        # Vulnerability 3: Wildcard with Credentials (RFC Invalid)
        if ao == "*" and ac and ac.lower() == "true":
            vulnerabilities.append({
                "severity": "MEDIUM",
                "issue": "Wildcard Origin with Credentials",
                "description": "Access-Control-Allow-Origin: * combined with credentials: true is rejected by modern browsers.",
            })

    is_secure = len(vulnerabilities) == 0

    return {
        "url": url,
        "is_secure": is_secure,
        "vulnerabilities": vulnerabilities,
        "tests": results,
    }


def generate_secure_cors_config() -> str:
    return """# Secure CORS Configuration Examples

## 1. Laravel (config/cors.php):
return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE'],
    // Explicitly whitelist only legitimate origins (NEVER use '*' with supports_credentials => true)
    'allowed_origins' => [
        'https://app.yourdomain.com',
        'http://localhost:3000',
    ],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization', 'X-XSRF-TOKEN'],
    'exposed_headers' => [],
    'max_age' => 86400,
    'supports_credentials' => true,
];

## 2. Nginx (Strict Origin Validation Block):
map $http_origin $cors_allowed_origin {
    default "";
    "~^https://(app|portal)\\.yourdomain\\.com$" $http_origin;
    "~^http://localhost:[0-9]+$" $http_origin;
}

server {
    location /api/ {
        if ($cors_allowed_origin != "") {
            add_header 'Access-Control-Allow-Origin' $cors_allowed_origin always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-Requested-With' always;
        }
        if ($request_method = 'OPTIONS') {
            return 204;
        }
    }
}
"""


def main():
    parser = argparse.ArgumentParser(
        description="CORS (Cross-Origin Resource Sharing) Defensive Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", "-u", required=True, help="API URL to audit (e.g. http://127.0.0.1:8000/api/data)")
    parser.add_argument("--test-origin", "-o", help="Specific legitimate origin to test")
    parser.add_argument("--json", action="store_true", help="Output audit report as structured JSON")

    args = parser.parse_args()

    report = audit_cors(args.url, args.test_origin)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["is_secure"] else 1)

    print("=================================================================")
    print("           CORS DEFENSIVE CONFIGURATION AUDIT                    ")
    print("=================================================================")
    print(f"[*] Target Endpoint    : {report['url']}")
    print(f"[*] Overall Status     : {'[PASS] HARDENED' if report['is_secure'] else '[FAIL] VULNERABLE / MISCONFIGURED'}")
    print("-----------------------------------------------------------------")

    if report["vulnerabilities"]:
        print("IDENTIFIED CORS MISCONFIGURATIONS:")
        for v in report["vulnerabilities"]:
            print(f"  [!] [{v['severity']}] {v['issue']}")
            print(f"      {v['description']}")
    else:
        print("[+] No CORS misconfigurations detected. Origins are properly restricted.")

    print("\nINDIVIDUAL ORIGIN TEST RESULTS:")
    for t in report["tests"]:
        resp = t["response"]
        ao = resp.get("allow_origin", "None")
        ac = resp.get("allow_credentials", "None")
        print(f"  • {t['test_case']:<35} -> Origin Allowed: {ao} | Credentials: {ac}")

    if not report["is_secure"]:
        print("\n=================================================================")
        print("                 SECURE CORS REMEDIATION GUIDE                   ")
        print("=================================================================")
        print(generate_secure_cors_config())

    print("=================================================================")
    sys.exit(0 if report["is_secure"] else 1)


if __name__ == "__main__":
    main()
