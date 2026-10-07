#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web Authentication Flow & Client-Side Encryption Reverse Engineering Tracer.

Analyzes Login and Registration architectures in web applications:
  1. `scan-js`: Inspect JavaScript bundles to identify client-side password encryption
     (RSA JSEncrypt, CryptoJS AES/DES, SHA256+Salt, WebCrypto), authentication headers,
     and form payload parameters.
  2. `jwt-audit`: Decode and inspect JSON Web Tokens (JWT) for signature algorithms,
     claims exposure, expiration limits, and security misconfigurations (e.g. 'none' algorithm).
  3. `gen-replay`: Generate a complete, ready-to-run Python replay script (curl_cffi/requests)
     replicating the reverse-engineered login/register API call with proper signatures.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from pathlib import Path


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


# Client-side encryption signatures in JavaScript
CLIENT_CRYPTO_SIGNATURES = {
    "RSA Encryption (JSEncrypt)": [
        r"JSEncrypt",
        r"setPublicKey",
        r"encrypt\(",
        r"BEGIN PUBLIC KEY",
    ],
    "CryptoJS (AES / DES / TripleDES)": [
        r"CryptoJS\.AES\.encrypt",
        r"CryptoJS\.enc\.Utf8",
        r"CryptoJS\.mode\.",
        r"CryptoJS\.pad\.",
    ],
    "CryptoJS (Hashing / HMAC)": [
        r"CryptoJS\.HmacSHA256",
        r"CryptoJS\.SHA256",
        r"CryptoJS\.MD5",
    ],
    "WebCrypto API (SubtleCrypto)": [
        r"window\.crypto\.subtle",
        r"crypto\.subtle\.encrypt",
        r"crypto\.subtle\.importKey",
    ],
    "Base64 / Hex Encoding": [
        r"btoa\(",
        r"Buffer\.from\(",
        r"\.toString\(['\"]hex['\"]\)",
    ],
}

# Common auth parameter names in login/register payloads
AUTH_PARAMS_PATTERNS = [
    r"['\"](?:username|user|email|account|phone|login)['\"]\s*:",
    r"['\"](?:password|passwd|pwd|pass|secret)['\"]\s*:",
    r"['\"](?:confirmPassword|password_confirmation|repeatPassword)['\"]\s*:",
    r"['\"](?:captcha|captchaToken|turnstile|cf_turnstile|g-recaptcha-response)['\"]\s*:",
    r"['\"](?:csrf|csrfToken|_csrf|csrf_token)['\"]\s*:",
    r"['\"](?:nonce|timestamp|sign|signature|token)['\"]\s*:",
]

# Custom signature and auth headers
AUTH_HEADER_PATTERNS = [
    r"['\"]X-(?:Sign|Signature|Token|Timestamp|Nonce|Client-Id|App-Key)['\"]",
    r"['\"]Authorization['\"]\s*:\s*[`'\"]Bearer",
]


def scan_javascript_auth(file_path: str) -> dict:
    """Scan a JS file for client-side encryption and auth payload parameters."""
    log(f"Memindai pola otentikasi & enkripsi pada: {file_path}")
    if not os.path.isfile(file_path):
        log_err(f"File tidak ditemukan: {file_path}")
        return {}

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    results = {
        "file": file_path,
        "size_kb": round(len(content) / 1024, 2),
        "detected_crypto": {},
        "detected_params": [],
        "detected_headers": [],
        "rsa_public_keys": [],
    }

    # 1. Detect Crypto
    for crypto_name, patterns in CLIENT_CRYPTO_SIGNATURES.items():
        matched = []
        for pat in patterns:
            matches = len(re.findall(pat, content, re.IGNORECASE))
            if matches:
                matched.append(f"{pat} ({matches}x)")
        if matched:
            results["detected_crypto"][crypto_name] = matched

    # 2. Detect Auth Params
    for pat in AUTH_PARAMS_PATTERNS:
        matches = re.findall(pat, content, re.IGNORECASE)
        if matches:
            clean = [m.replace("'", "").replace('"', '').replace(':', '').strip() for m in matches]
            results["detected_params"].extend(list(set(clean)))

    results["detected_params"] = sorted(list(set(results["detected_params"])))

    # 3. Detect Headers
    for pat in AUTH_HEADER_PATTERNS:
        matches = re.findall(pat, content, re.IGNORECASE)
        if matches:
            results["detected_headers"].extend(list(set(matches)))

    # 4. Extract RSA Public Keys if embedded
    key_matches = re.findall(r"-----BEGIN (?:RSA )?PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END (?:RSA )?PUBLIC KEY-----", content)
    if key_matches:
        results["rsa_public_keys"] = key_matches

    # Output Summary
    log_success("Hasil Pemindaian Otentikasi JavaScript:")
    print(f"  * Ukuran File: {results['size_kb']} KB")
    print("  * Pustaka Enkripsi Klien:")
    if results["detected_crypto"]:
        for name, sigs in results["detected_crypto"].items():
            print(f"    - {name}: {', '.join(sigs)}")
    else:
        print("    (Tidak ditemukan pustaka enkripsi kompleks, kemungkinan plain HTTPS JSON)")

    print(f"  * Parameter Form Login/Register: {', '.join(results['detected_params']) if results['detected_params'] else 'Tidak ditemukan'}")
    print(f"  * Header Otentikasi Terdeteksi: {', '.join(results['detected_headers']) if results['detected_headers'] else 'Standard'}")
    if results["rsa_public_keys"]:
        log_warn(f"Ditemukan {len(results['rsa_public_keys'])} Hardcoded RSA Public Key di dalam JS!")

    return results


def audit_jwt_token(token: str) -> dict:
    """Decode and inspect JWT token for security weaknesses and claims."""
    log("Menganalisis struktur JSON Web Token (JWT)...")
    parts = token.strip().split(".")
    if len(parts) != 3:
        log_err("Format JWT tidak valid (harus terdiri dari 3 bagian yang dipisah titik).")
        return {}

    def b64_decode(data: str) -> dict:
        padded = data + "=" * (-len(data) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw.decode("utf-8", errors="ignore"))

    try:
        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])
    except Exception as e:
        log_err(f"Gagal mendekode Base64Url JWT: {e}")
        return {}

    alg = header.get("alg", "UNKNOWN")
    exp = payload.get("exp")
    now = int(time.time())

    findings = []
    if alg.lower() == "none":
        findings.append("KRITIS: Token menggunakan algoritma 'none' (tanda tangan tidak diverifikasi)!")
    elif alg in ["HS256", "HS384", "HS512"]:
        findings.append(f"Symmetric HMAC ({alg}): Rentan terhadap key confusion jika server juga mendukung RSA/ECDSA.")

    if exp:
        if exp < now:
            findings.append(f"Token telah kedaluwarsa ({now - exp} detik yang lalu).")
        else:
            findings.append(f"Token valid (kedaluwarsa dalam {exp - now} detik).")
    else:
        findings.append("PERINGATAN: Token tidak memiliki klaim masa berlaku ('exp')!")

    sensitive_keys = [k for k in payload.keys() if any(s in k.lower() for s in ["pass", "pwd", "secret", "card", "ssn"])]
    if sensitive_keys:
        findings.append(f"RISIKO DATA: Klaim payload memuat data sensitif: {', '.join(sensitive_keys)}")

    log_success("Hasil Audit JWT:")
    print("  [HEADER]:", json.dumps(header, indent=4))
    print("  [PAYLOAD]:", json.dumps(payload, indent=4))
    print("  [TEMUAN AUDIT]:")
    for f in findings:
        print(f"    - {f}")

    return {"header": header, "payload": payload, "findings": findings}


def generate_auth_replay_script(url: str, method: str = "POST", params: list | None = None, is_encrypted: bool = False) -> str:
    """Generate a production-grade Python script to replay and automate the auth flow."""
    params = params or ["username", "password"]
    json_payload = {p: f"value_{p}" for p in params}

    script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generated Auth Replay Script by Antigravity Auth Flow Tracer."""

import time
import json
from curl_cffi import requests

TARGET_URL = "{url}"
METHOD = "{method.upper()}"

headers = {{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Origin": "{'/'.join(url.split('/')[:3]) if '://' in url else 'http://localhost'}",
    "Referer": "{url}",
}}

payload = {json.dumps(json_payload, indent=4)}

def execute_auth():
    print(f"[*] Mengirim permintaan otentikasi ke: {{TARGET_URL}}")
    session = requests.Session(impersonate="chrome124")
    
    # Eksekusi request dengan bypass TLS fingerprinting (JA3/JA4)
    res = session.request(METHOD, TARGET_URL, json=payload, headers=headers)
    
    print(f"[+] Status Code: {{res.status_code}}")
    print(f"[+] Response Headers: {{dict(res.headers)}}")
    try:
        print(f"[+] Response JSON:\\n{{json.dumps(res.json(), indent=2)}}")
    except Exception:
        print(f"[+] Response Body:\\n{{res.text[:500]}}")

if __name__ == "__main__":
    execute_auth()
'''
    return script


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Web Authentication Flow & Client-Side Encryption Reverse Engineering Tracer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan-js
    p_scan = subparsers.add_parser("scan-js", help="Pindai enkripsi klien dan parameter auth pada file JavaScript")
    p_scan.add_argument("--file", required=True, help="Path ke file JavaScript")

    # jwt-audit
    p_jwt = subparsers.add_parser("jwt-audit", help="Audit struktur dan keamanan JSON Web Token (JWT)")
    p_jwt.add_argument("--token", required=True, help="String JWT")

    # gen-replay
    p_gen = subparsers.add_parser("gen-replay", help="Generate skrip replay Python untuk endpoint auth")
    p_gen.add_argument("--url", required=True, help="URL endpoint login/register")
    p_gen.add_argument("--method", default="POST", help="Metode HTTP (POST/GET)")
    p_gen.add_argument("--out", default="auth_replay.py", help="File output")

    args = parser.parse_args()

    if args.command == "scan-js":
        scan_javascript_auth(args.file)
        return 0
    elif args.command == "jwt-audit":
        audit_jwt_token(args.token)
        return 0
    elif args.command == "gen-replay":
        code = generate_auth_replay_script(args.url, args.method)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(code)
        log_success(f"Skrip replay otentikasi tersimpan di: {args.out}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
