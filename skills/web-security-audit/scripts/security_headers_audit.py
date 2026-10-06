#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web Security Headers & Cookie Flags Defensive Auditor.

WHY THIS EXISTS
---------------
Web applications often lack essential defensive HTTP security headers and cookie flags,
leaving users vulnerable to Clickjacking, Cross-Site Scripting (XSS), MIME-sniffing,
and session hijacking.

This tool audits an HTTP/HTTPS endpoint against OWASP Secure Headers Project standards:
  1. Content-Security-Policy (CSP)
  2. Strict-Transport-Security (HSTS)
  3. X-Frame-Options (Clickjacking defense)
  4. X-Content-Type-Options (MIME-sniffing defense)
  5. Referrer-Policy (Privacy and token leakage defense)
  6. Permissions-Policy (Hardware feature restriction)
  7. Cookie Flags: HttpOnly, Secure, SameSite (Session protection)
  8. Information Disclosure: Server, X-Powered-By, X-AspNet-Version leak detection

It grades the security posture (A+ to F) and automatically outputs ready-to-copy
remediation configurations for Nginx, Apache, and Laravel middleware!

USAGE
-----
  # Audit a local or remote web application
  python security_headers_audit.py --url http://127.0.0.1:8000

  # Audit HTTPS domain and generate Nginx / Apache fix config
  python security_headers_audit.py --url https://example.com --generate-config nginx

  # Output structured JSON audit report
  python security_headers_audit.py --url http://127.0.0.1:8000 --json

EXIT CODES
----------
  0 = audit completed (grade A or B)
  1 = audit completed with warnings/failures (grade C, D, or F)
  2 = network error or invalid arguments
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import ssl
from pathlib import Path


RECOMMENDED_HEADERS = {
    "Content-Security-Policy": {
        "description": "Restricts sources of executable scripts, stylesheets, and resources (XSS mitigation).",
        "weight": 25,
        "recommended_value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
        "weight": 20,
        "recommended_value": "max-age=31536000; includeSubDomains; preload",
        "https_only": True,
    },
    "X-Frame-Options": {
        "description": "Prevents the website from being embedded inside an iframe (Clickjacking defense).",
        "weight": 15,
        "recommended_value": "DENY",
    },
    "X-Content-Type-Options": {
        "description": "Prevents browsers from MIME-sniffing a response away from the declared Content-Type.",
        "weight": 10,
        "recommended_value": "nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent when navigating away from the page.",
        "weight": 10,
        "recommended_value": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Restricts browser access to hardware APIs (geolocation, camera, microphone).",
        "weight": 10,
        "recommended_value": "camera=(), microphone=(), geolocation=(), payment=()",
    },
}

INFO_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
]


def audit_endpoint(url: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Web-Security-Auditor/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_headers = dict(resp.headers)
            status_code = resp.getcode()
            cookies = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        raw_headers = dict(e.headers)
        status_code = e.code
        cookies = e.headers.get_all("Set-Cookie") or []
    except Exception as e:
        raise RuntimeError(f"Failed to connect to {url}: {e}")

    is_https = url.lower().startswith("https://")
    total_score = 0
    max_score = 0
    findings = []

    # 1. Audit Security Headers
    for header_name, meta in RECOMMENDED_HEADERS.items():
        if meta.get("https_only") and not is_https:
            continue

        max_score += meta["weight"]
        lower_name = header_name.lower()

        if lower_name in headers:
            total_score += meta["weight"]
            findings.append({
                "header": header_name,
                "status": "PASS",
                "value": headers[lower_name],
                "description": meta["description"],
            })
        else:
            findings.append({
                "header": header_name,
                "status": "MISSING",
                "recommendation": meta["recommended_value"],
                "description": meta["description"],
            })

    # 2. Audit Information Disclosure
    disclosed_info = []
    for info_header in INFO_DISCLOSURE_HEADERS:
        if info_header in headers:
            disclosed_info.append({
                "header": info_header,
                "value": headers[info_header],
                "risk": "Information Disclosure (leaks technology stack version)",
            })
            total_score = max(0, total_score - 5)

    # 3. Audit Cookies
    cookie_findings = []
    for cookie_str in cookies:
        cookie_parts = [p.strip() for p in cookie_str.split(";")]
        c_name = cookie_parts[0].split("=")[0] if cookie_parts else "unknown"
        lower_parts = [p.lower() for p in cookie_parts]

        has_httponly = "httponly" in lower_parts
        has_secure = "secure" in lower_parts
        samesite = "none"
        for p in lower_parts:
            if p.startswith("samesite="):
                samesite = p.split("=")[1]

        cookie_findings.append({
            "cookie": c_name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite,
            "is_hardened": has_httponly and (has_secure or not is_https) and samesite in ["lax", "strict"],
        })

    # Grade Calculation
    percentage = (total_score / max_score * 100) if max_score > 0 else 0
    if percentage >= 90:
        grade = "A+" if not disclosed_info else "A"
    elif percentage >= 80:
        grade = "B"
    elif percentage >= 65:
        grade = "C"
    elif percentage >= 50:
        grade = "D"
    else:
        grade = "F"

    return {
        "url": url,
        "is_https": is_https,
        "status_code": status_code,
        "grade": grade,
        "score_percentage": round(percentage, 1),
        "security_headers": findings,
        "information_disclosure": disclosed_info,
        "cookie_audit": cookie_findings,
        "raw_headers": raw_headers,
    }


def generate_remediation_configs(target_format: str) -> str:
    if target_format == "nginx":
        return """# Nginx Security Headers Remediation Config
# Paste inside your server {} or location / {} block:

add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;

# Disable version disclosure
server_tokens off;
"""
    elif target_format == "apache":
        return """# Apache (.htaccess or VirtualHost) Security Headers Remediation Config
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    Header unset X-Powered-By
</IfModule>
ServerSignature Off
ServerTokens Prod
"""
    elif target_format == "laravel":
        return r"""<?php
// Laravel Security Headers Middleware
// App/Http/Middleware/SecurityHeadersMiddleware.php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
        
        if ($request->isSecure()) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        }

        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");
        $response->headers->remove('X-Powered-By');

        return $response;
    }
}
"""
    return "# Format not recognized"


def main():
    parser = argparse.ArgumentParser(
        description="Web Security Headers & Cookie Flags Defensive Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", "-u", required=True, help="Target URL to audit (e.g. http://127.0.0.1:8000 or https://example.com)")
    parser.add_argument("--generate-config", "-g", choices=["nginx", "apache", "laravel"], help="Generate ready-to-use hardening config")
    parser.add_argument("--json", action="store_true", help="Output audit report as structured JSON")

    args = parser.parse_args()

    try:
        report = audit_endpoint(args.url)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        if args.generate_config:
            report["remediation_config"] = generate_remediation_configs(args.generate_config)
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["grade"] in ["A+", "A", "B"] else 1)

    print("=================================================================")
    print("           WEB SECURITY HEADERS & COOKIE DEFENSIVE AUDIT         ")
    print("=================================================================")
    print(f"[*] Target URL         : {report['url']}")
    print(f"[*] Response Status    : {report['status_code']}")
    print(f"[*] HTTPS Enforced     : {report['is_https']}")
    print(f"[*] Security Score     : {report['score_percentage']}%")
    print(f"[*] Overall Grade      : [{report['grade']}]")
    print("-----------------------------------------------------------------")
    print("SECURITY HEADERS AUDIT:")
    for h in report["security_headers"]:
        if h["status"] == "PASS":
            print(f"  [+] PASS    : {h['header']:<28} = {h['value'][:50]}")
        else:
            print(f"  [-] MISSING : {h['header']:<28} (Recommended: {h['recommendation'][:40]}...)")

    if report["information_disclosure"]:
        print("\nINFORMATION DISCLOSURE WARNINGS:")
        for leak in report["information_disclosure"]:
            print(f"  [!] LEAK    : {leak['header']:<28} = {leak['value']} ({leak['risk']})")

    if report["cookie_audit"]:
        print("\nCOOKIE SECURITY ATTRIBUTES:")
        for c in report["cookie_audit"]:
            status_flag = "[+]" if c["is_hardened"] else "[-]"
            print(f"  {status_flag} Cookie '{c['cookie']}': HttpOnly={c['httponly']}, Secure={c['secure']}, SameSite={c['samesite']}")

    if args.generate_config:
        print("\n=================================================================")
        print(f"       GENERATED REMEDIATION CONFIG ({args.generate_config.upper()})     ")
        print("=================================================================")
        print(generate_remediation_configs(args.generate_config))

    print("=================================================================")
    sys.exit(0 if report["grade"] in ["A+", "A", "B"] else 1)


if __name__ == "__main__":
    main()
