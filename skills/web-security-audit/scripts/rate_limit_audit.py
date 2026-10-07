#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rate Limiting & Anti-Automation Defensive Auditor.

Audits web applications and API route definitions for missing Rate Limiting / Throttling
on high-risk endpoints susceptible to:
  1. Credential Stuffing & Password Brute-Force (Login / Reset Password)
  2. OTP SMS Flooding & Telephony Toll Fraud (Send OTP / SMS Verification)
  3. Sybil Account Generation (Registration / Sign-up spam)
  4. Coupon / Voucher Race Conditions & Financial Drain (Checkout / Redeem)
  5. API Scraping & Resource Exhaustion (Search / Export endpoints)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def log_err(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


# High-risk keywords indicating sensitive endpoints requiring strict rate limits
SENSITIVE_ENDPOINT_KEYWORDS = [
    r"login",
    r"signin",
    r"register",
    r"signup",
    r"password[/-]reset",
    r"forgot[/-]password",
    r"reset[/-]password",
    r"send[/-]otp",
    r"verify[/-]otp",
    r"send[/-]code",
    r"sms",
    r"checkout",
    r"redeem",
    r"coupon",
    r"voucher",
    r"transfer",
]

# Known rate limiting middleware markers across frameworks
RATE_LIMIT_MARKERS = [
    # Laravel
    r"throttle:",
    r"ThrottleRequests",
    r"RateLimiter::for",
    # Express / Node
    r"rateLimit\(",
    r"express-rate-limit",
    r"limiter",
    r"slowDown",
    # Python FastAPI / Flask / Django
    r"@limiter\.limit",
    r"ratelimit\(",
    r"slowapi",
    r"django_ratelimit",
    # Nginx
    r"limit_req\s+zone=",
]


def audit_route_content(file_path: Path, content: str) -> list[dict]:
    """Scan route definitions for sensitive endpoints missing rate limiting."""
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines):
        line_num = idx + 1
        line_lower = line.lower()

        # Check if line defines a route (Laravel Route::, Express app.post/router.post, FastAPI @app.post/@router.post)
        is_route_def = bool(re.search(r"""(?:Route::(?:post|get|put|delete|match|any)|(?:app|router)\.(?:post|get|put|delete)|@(?:app|router)\.(?:post|get|put|delete))\s*\(""", line, re.IGNORECASE))
        if not is_route_def:
            continue

        # Check if route targets a sensitive operation
        matched_sensitive = None
        for kw in SENSITIVE_ENDPOINT_KEYWORDS:
            if re.search(kw, line_lower):
                matched_sensitive = kw
                break

        if not matched_sensitive:
            continue

        # Look in the current line and nearby surrounding lines (next 3 lines) for throttle/rate-limit middleware
        surrounding = "\n".join(lines[idx : min(idx + 4, len(lines))])
        has_throttle = any(re.search(marker, surrounding, re.IGNORECASE) for marker in RATE_LIMIT_MARKERS)

        if not has_throttle:
            findings.append({
                "line": line_num,
                "endpoint_type": matched_sensitive,
                "snippet": line.strip(),
                "desc": f"Endpoint sensitif ('{matched_sensitive}') tidak menyertakan middleware rate limiting/throttling.",
            })

    return findings


def scan_rate_limits(target_path: str) -> None:
    """Scan routes and controllers in target directory."""
    p = Path(target_path)
    if not p.exists():
        log_err(f"Target path tidak ditemukan: {target_path}")
        return

    exts = [".php", ".js", ".ts", ".py", ".conf"]
    files = [p] if p.is_file() else [f for ext in exts for f in p.rglob(f"*{ext}")]

    log(f"Memulai audit Rate Limiting & Anti-Automation pada {len(files)} file...")

    total_unprotected = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        findings = audit_route_content(f, content)
        if findings:
            total_unprotected += len(findings)
            print("\n" + "=" * 75)
            log_warn(f"FILE: {f.resolve()}")
            print("=" * 75)
            for item in findings:
                print(f"  [PERINGATAN TINGGI] Baris {item['line']}: {item['desc']}")
                print(f"      Kode      : {item['snippet']}")

    print("\n" + "#" * 50)
    print("      RINGKASAN AUDIT RATE LIMITING")
    print("#" * 50)
    print(f"  Total Endpoint Sensitif Tanpa Rate Limit : {total_unprotected}")
    print("#" * 50)

    if total_unprotected > 0:
        log_warn("Ditemukan endpoint berisiko tinggi tanpa proteksi throttling.")
        print("Gunakan subcommand 'remediate' untuk melihat konfigurasi rate limiter.")
    else:
        log_success("Tidak terdeteksi rute sensitif yang kehilangan pembatas laju.")


def print_rate_limit_remediation() -> None:
    """Print production-grade rate limiting architectures."""
    recipes = """
================================================================================
     PANDUAN REMEDIASI RATE LIMITING & ANTI-AUTOMATION (REDIS / SLIDING WINDOW)
================================================================================

1. Laravel 10/11 - Custom Rate Limiter (RouteServiceProvider / AppServiceProvider):
--------------------------------------------------------------------------------
// [A] DEFINISI RATE LIMITER SPESIFIK
RateLimiter::for('auth-login', function (Request $request) {
    // Batasi 5 percobaan per menit berdasarkan kombinasi email + IP
    return Limit::perMinute(5)
        ->by($request->input('email') . '|' . $request->ip())
        ->response(function () {
            return response()->json(['error' => 'Terlalu banyak percobaan login. Silakan tunggu 1 menit.'], 429);
        });
});

RateLimiter::for('otp-sms', function (Request $request) {
    // Batasi 3 pengiriman OTP per 10 menit untuk cegah SMS Toll Fraud
    return Limit::perMinutes(10, 3)->by($request->input('phone') . '|' . $request->ip());
});

// [B] PENERAPAN DI ROUTES (routes/api.php)
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:auth-login');
Route::post('/send-otp', [OtpController::class, 'sendOtp'])->middleware('throttle:otp-sms');


2. Node.js (Express & express-rate-limit + Redis Store):
--------------------------------------------------------------------------------
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redisClient = require('./redisClient');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Menit
  max: 5, // Maksimal 5 percobaan
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Terlalu banyak percobaan login gagal. Akun dikunci sementara selama 15 menit.' },
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args),
  }),
});

app.post('/api/auth/login', loginLimiter, authController.login);


3. Nginx Web Server - Leaky Bucket Rate Limiting:
--------------------------------------------------------------------------------
# Di blok http:
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api_general:10m rate=30r/s;

# Di blok server / location:
location /api/auth/ {
    limit_req zone=auth_limit burst=3 nodelay;
    limit_req_status 429;
    proxy_pass http://backend_upstream;
}
================================================================================
"""
    print(recipes)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rate Limiting & Anti-Automation Defensive Auditor"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_audit = subparsers.add_parser("audit", help="Audit rute dan endpoint terhadap celah ketiadaan rate limit")
    p_audit.add_argument("path", help="Path direktori atau file rute target")

    p_rem = subparsers.add_parser("remediate", help="Tampilkan konfigurasi Rate Limiting Redis & Nginx")

    args = parser.parse_args()
    if args.command == "audit":
        scan_rate_limits(args.path)
    elif args.command == "remediate":
        print_rate_limit_remediation()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
