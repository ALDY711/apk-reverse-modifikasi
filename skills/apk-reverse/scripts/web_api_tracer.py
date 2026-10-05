#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trace, analyze, and reverse engineer Web API signatures, tokens, and encryption in JavaScript bundles.

WHY THIS EXISTS
---------------
Modern web applications, single-page apps (React/Vue/Angular), and mobile WebViews often protect
their internal APIs using client-side dynamic signatures (e.g. `X-Sign`, `_signature`, `token`,
`nonce`, or custom HMAC/MD5/AES digests).

To call these endpoints directly from Python, cURL, or automated scripts, an analyst must:
  1. Identify where requests are built (Axios interceptors, fetch wrappers, XMLHttpRequest).
  2. Locate the exact JavaScript functions that compute the signature or token.
  3. Determine which parameters (URL, query string, timestamp, request body, salt) feed into the hash.
  4. Identify the cryptographic primitive (MD5, SHA-256, HMAC-SHA256, AES-CBC, SM3/SM4).

This script performs static pattern analysis across minified or formatted JavaScript files
to pinpoint signature generation sites, extracted cryptographic algorithms, request interceptors,
and endpoint URL patterns.

USAGE
-----
  # Trace signature and token logic in a local JS bundle
  python web_api_tracer.py --file app.bundle.js

  # Fetch and analyze a remote JS file directly
  python web_api_tracer.py --url https://example.com/static/js/app.js

  # Focus specifically on custom headers (e.g. X-Sign or Authorization)
  python web_api_tracer.py --file app.js --query "X-Sign"

  # Output structured JSON report
  python web_api_tracer.py --file app.js --json

EXIT CODES
----------
  0 = signature patterns or cryptographic routines found
  1 = no signature patterns found
  2 = usage or argument error
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
from pathlib import Path


def _decode_jwt_payload(token: str) -> dict | None:
    """Safely decode the JSON claims payload of a JWT token."""
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            payload_b64 = parts[1]
            padded = payload_b64 + '=' * ((4 - len(payload_b64) % 4) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            parsed = json.loads(decoded_bytes.decode('utf-8', errors='replace'))
            if isinstance(parsed, dict):
                return parsed
    except Exception:
        pass
    return None


# Signature-related keywords and parameters
SIGNATURE_KEYWORDS = [
    r'x-sign(?:ature)?',
    r'x-token',
    r'x-auth(?:-token)?',
    r'x-timestamp',
    r'x-nonce',
    r'authorization',
    r'[''"]_?sig(?:nature)?[''"]',
    r'[''"]token[''"]',
    r'[''"]nonce[''"]',
    r'[''"]timestamp[''"]',
    r'[''"]app_?key[''"]',
    r'[''"]app_?secret[''"]',
    r'[''"]sign_?type[''"]',
    r'[?&](?:sign|signature|_sig|token|nonce|ts|timestamp)=',
]

# Cryptographic and hashing primitives
CRYPTO_PATTERNS = [
    (r'\bCryptoJS\b', 'CryptoJS library usage'),
    (r'\b(?:md5|MD5)\b', 'MD5 hashing'),
    (r'\b(?:sha1|SHA1)\b', 'SHA-1 hashing'),
    (r'\b(?:sha256|SHA256)\b', 'SHA-256 hashing'),
    (r'\b(?:sha512|SHA512)\b', 'SHA-512 hashing'),
    (r'\b(?:Hmac|HMAC)\b', 'HMAC keyed-hash algorithm'),
    (r'\b(?:AES|aes)\b', 'AES encryption/decryption'),
    (r'\b(?:RSA|rsa)\b', 'RSA public-key cryptography'),
    (r'\b(?:sm3|SM3)\b', 'SM3 Chinese national standard hash'),
    (r'\b(?:sm4|SM4)\b', 'SM4 Chinese national standard cipher'),
    (r'\bcrypto\.subtle\.digest\b', 'Web Crypto API digest'),
    (r'\bbtoa\b|\batob\b', 'Base64 encoding/decoding'),
]

# HTTP clients and interceptors
INTERCEPTOR_PATTERNS = [
    (r'\binterceptors\.request\.use\b', 'Axios request interceptor (prime signature injection site)'),
    (r'\baxios\.create\b', 'Axios client instance initialization'),
    (r'\bwindow\.fetch\b|\bfetch\(', 'Fetch API wrapper'),
    (r'\bsetRequestHeader\b', 'XMLHttpRequest header injection site'),
    (r'\buni\.request\b', 'Uni-app mobile web request wrapper'),
    (r'\bnew\s+WebSocket\b', 'WebSocket connection establishment'),
    (r'\bio\s*\(|\bsocket\.io\b', 'Socket.IO client connection'),
    (r'\bnew\s+EventSource\b', 'Server-Sent Events (SSE) stream'),
]

# Endpoint extraction regex
ENDPOINT_PATTERN = re.compile(r'["\'](/(?:api|v[0-9]|rest|auth|user|login|app)/[A-Za-z0-9_\-\./?=&]+)["\']')

# JWT token regex pattern (header.payload.signature)
JWT_PATTERN = re.compile(r'\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-\.\+\/=]*)\b')


def fetch_js_content(url: str) -> str:
    """Fetch JavaScript file content from URL."""
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode('utf-8', errors='replace')


def extract_context_snippet(text: str, start_pos: int, end_pos: int, context_chars: int = 140) -> str:
    """Extract a surrounding window of text around a match."""
    left = max(0, start_pos - context_chars)
    right = min(len(text), end_pos + context_chars)
    snippet = text[left:right].replace('\n', ' ').strip()
    return f"... {snippet} ..."


def analyze_javascript(content: str, custom_query: str | None = None) -> dict:
    """Scan JavaScript text for signatures, cryptography, and network interceptors."""
    results = {
        'signature_candidates': [],
        'crypto_primitives': [],
        'interceptors': [],
        'endpoints_found': [],
        'jwt_tokens': [],
    }

    # 1. Custom query search if provided
    if custom_query:
        query_re = re.compile(re.escape(custom_query), re.IGNORECASE)
        for m in query_re.finditer(content):
            results['signature_candidates'].append({
                'keyword': custom_query,
                'position': m.start(),
                'snippet': extract_context_snippet(content, m.start(), m.end())
            })
    else:
        # Default signature keywords search
        for pattern in SIGNATURE_KEYWORDS:
            kw_re = re.compile(pattern, re.IGNORECASE)
            for m in list(kw_re.finditer(content))[:15]:  # Limit hits per keyword to avoid flooding
                results['signature_candidates'].append({
                    'pattern': pattern,
                    'matched': m.group(0),
                    'position': m.start(),
                    'snippet': extract_context_snippet(content, m.start(), m.end())
                })

    # 2. Cryptographic algorithm matches
    for pattern, desc in CRYPTO_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            first_match = matches[0]
            results['crypto_primitives'].append({
                'algorithm': desc,
                'count': len(matches),
                'first_position': first_match.start(),
                'snippet': extract_context_snippet(content, first_match.start(), first_match.end())
            })

    # 3. Interceptors and network hooks
    for pattern, desc in INTERCEPTOR_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            first_match = matches[0]
            results['interceptors'].append({
                'type': desc,
                'count': len(matches),
                'snippet': extract_context_snippet(content, first_match.start(), first_match.end())
            })

    # 4. Extract sample API endpoints
    endpoints = set()
    for m in ENDPOINT_PATTERN.finditer(content):
        endpoints.add(m.group(1))
        if len(endpoints) >= 20:
            break
    results['endpoints_found'] = sorted(list(endpoints))

    # 5. Extract and decode static JWT tokens if present
    seen_jwts = set()
    for m in JWT_PATTERN.finditer(content):
        raw_jwt = m.group(1)
        if raw_jwt in seen_jwts:
            continue
        seen_jwts.add(raw_jwt)
        claims = _decode_jwt_payload(raw_jwt)
        results['jwt_tokens'].append({
            'token_preview': raw_jwt[:35] + '...' if len(raw_jwt) > 40 else raw_jwt,
            'position': m.start(),
            'claims': claims or 'Unable to parse claims'
        })
        if len(results['jwt_tokens']) >= 5:
            break

    return results


def main():
    parser = argparse.ArgumentParser(
        prog='web_api_tracer',
        description='Trace API signatures, tokens, and cryptographic functions in JavaScript bundles',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', help='Path to local JavaScript file')
    group.add_argument('--url', help='URL of JavaScript file to download and inspect')

    parser.add_argument('--query', help='Specific parameter or header to trace (e.g. X-Sign, token)')
    parser.add_argument('--json', action='store_true', help='Output machine-readable JSON summary')

    args = parser.parse_args()

    # Load content
    target_name = args.file or args.url
    try:
        if args.file:
            path = Path(args.file)
            if not path.is_file():
                sys.stderr.write(f"[ERROR] File tidak ditemukan: {args.file}\n")
                return 2
            content = path.read_text(encoding='utf-8', errors='replace')
        else:
            content = fetch_js_content(args.url)
    except Exception as e:
        sys.stderr.write(f"[ERROR] Gagal membaca target {target_name}: {e}\n")
        return 1

    findings = analyze_javascript(content, args.query)
    total_findings = (
        len(findings['signature_candidates']) +
        len(findings['crypto_primitives']) +
        len(findings['interceptors'])
    )

    report = {
        'status': 'ok' if total_findings > 0 else 'no_findings',
        'target': target_name,
        'size_bytes': len(content),
        'findings': findings
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n" + "=" * 65)
        print("  🔍 HASIL ANALISIS SIGNATURE & TOKEN WEB API")
        print("=" * 65)
        print(f"  Target:     {target_name} ({len(content)} bytes)")
        print(f"  Kandidat:   {len(findings['signature_candidates'])} signature/token sites")
        print(f"  Kripto:     {len(findings['crypto_primitives'])} algoritma terdeteksi")
        print(f"  Interceptor:{len(findings['interceptors'])} hook request ditemukan")
        print("=" * 65)

        if findings['interceptors']:
            print("\n  [📡 HTTP INTERCEPTORS / HOOKS]")
            for item in findings['interceptors']:
                print(f"    * {item['type']} (muncul {item['count']}x)")
                print(f"      {item['snippet']}")

        if findings['crypto_primitives']:
            print("\n  [🔐 ALGORITMA KRIPTOGRAFI / HASH]")
            for item in findings['crypto_primitives']:
                print(f"    * {item['algorithm']} ({item['count']}x)")
                print(f"      {item['snippet']}")

        if findings['signature_candidates']:
            print("\n  [🎯 POTONGAN KODE PEMBENTUK SIGNATURE / TOKEN]")
            for item in findings['signature_candidates'][:8]:
                label = item.get('matched') or item.get('keyword') or item.get('pattern')
                print(f"    * Cocok: '{label}' di offset {item['position']}")
                print(f"      {item['snippet']}")

        if findings['endpoints_found']:
            print("\n  [🌐 CONTOH ENDPOINT API YANG DITEMUKAN]")
            for ep in findings['endpoints_found'][:10]:
                print(f"    - {ep}")

        if findings['jwt_tokens']:
            print("\n  [🔑 JWT TOKEN / CLAIMS TERDETEKSI]")
            for jwt_item in findings['jwt_tokens']:
                print(f"    * Token: {jwt_item['token_preview']} (pos: {jwt_item['position']})")
                print(f"      Claims: {json.dumps(jwt_item['claims'])}")

        print()

    return 0 if total_findings > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
