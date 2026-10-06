#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare cookie inspector and validation tool.

WHY THIS EXISTS
---------------
A `cf_clearance` cookie that passes visual inspection can still fail because:
  1. The User-Agent used during replay differs from the one used during solve.
  2. The TLS fingerprint (JA3/JA4) of the replay client differs from the solver browser.
  3. The cookie has expired (Cloudflare default TTL is ~20-30 minutes).
  4. The cookie was issued for a different domain.

This tool:
  1. Decodes and displays cf_clearance cookie metadata.
  2. Validates that a cookie+UA pair can access a target domain (test request).
  3. Inspects Cloudflare response headers to diagnose bypass failures.
  4. Reports cf-ray, server, cf-cache-status for debugging.

USAGE
-----
  # Validate a cookie against a domain
  python cf_cookie_inspector.py --url "https://target.com" --cookie "cf_clearance=abc..." --ua "Mozilla/5.0..."

  # Inspect a cookie value offline (decode metadata)
  python cf_cookie_inspector.py --cookie "cf_clearance=abc123..." --ua "Mozilla/5.0..."

  # Inspect saved sessions from cf_session.py
  python cf_cookie_inspector.py --sessions
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import hashlib
import base64

SESSION_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".cf_sessions.json")


def analyze_cookie(cookie_value: str) -> dict:
    """Extract observable metadata from cf_clearance cookie value."""
    result = {
        "raw_value": cookie_value,
        "length": len(cookie_value),
        "likely_valid_format": len(cookie_value) > 30,
    }

    # cf_clearance cookies are typically base64-ish or hex-encoded blobs.
    # We can't decrypt them (server-side key) but we can characterize them.
    if "-" in cookie_value:
        parts = cookie_value.split("-")
        result["segments"] = len(parts)
        result["segment_lengths"] = [len(p) for p in parts]
    else:
        result["segments"] = 1

    # Check encoding characteristics
    try:
        decoded = base64.urlsafe_b64decode(cookie_value + "==")
        result["base64_decodable"] = True
        result["decoded_length"] = len(decoded)
    except Exception:
        result["base64_decodable"] = False

    return result


def validate_cookie(url: str, cookie_value: str, user_agent: str) -> dict:
    """Test if the cf_clearance cookie grants access to the target URL."""
    # Ensure cookie is just the value, not the full cookie string
    if cookie_value.startswith("cf_clearance="):
        cookie_value = cookie_value[len("cf_clearance="):]

    headers = {
        "User-Agent": user_agent,
        "Cookie": f"cf_clearance={cookie_value}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
    }

    req = urllib.request.Request(url, headers=headers)
    start = time.time()

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            elapsed = time.time() - start
            body = res.read().decode("utf-8", errors="replace")
            resp_headers = dict(res.headers)

            cf_headers = {k: v for k, v in resp_headers.items()
                          if k.lower().startswith("cf-") or k.lower() == "server"}

            # Check if response is still a challenge page
            is_challenge = any(ind in body for ind in [
                "Just a moment...", "Attention Required!", "cf-browser-verification",
                "cf-challenge-running", "cf-turnstile", "cf_chl_opt"
            ])

            return {
                "valid": not is_challenge,
                "status_code": res.status,
                "content_length": len(body),
                "is_challenge": is_challenge,
                "elapsed": f"{elapsed:.2f}s",
                "cloudflare_headers": cf_headers,
                "behind_cloudflare": "cf-ray" in [k.lower() for k in resp_headers],
                "warning": (
                    "Cookie might work but TLS fingerprint of Python urllib differs from Chrome. "
                    "If you get 403, try got-scraping (Node.js) or curl_cffi (Python) instead."
                ) if not is_challenge else None
            }
    except urllib.error.HTTPError as err:
        elapsed = time.time() - start
        resp_headers = dict(err.headers) if err.headers else {}
        cf_headers = {k: v for k, v in resp_headers.items()
                      if k.lower().startswith("cf-") or k.lower() == "server"}

        diagnosis = "Unknown"
        if err.code == 403:
            diagnosis = (
                "HTTP 403 Forbidden — Most likely cause: TLS fingerprint mismatch. "
                "The cf_clearance was solved by Chrome but replayed by Python urllib "
                "which has a completely different JA3/JA4 fingerprint. "
                "Use got-scraping (Node.js) or curl_cffi (Python) for replay."
            )
        elif err.code == 503:
            diagnosis = "HTTP 503 — Cloudflare challenge still active, cookie may be expired."

        return {
            "valid": False,
            "status_code": err.code,
            "elapsed": f"{elapsed:.2f}s",
            "diagnosis": diagnosis,
            "cloudflare_headers": cf_headers,
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def list_sessions() -> list:
    """Load and display saved sessions from cf_session.py's cache."""
    if not os.path.exists(SESSION_CACHE_FILE):
        return []
    try:
        with open(SESSION_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return list(data.values())
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Cookie Inspector & Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate cookie against target
  python cf_cookie_inspector.py --url https://example.com --cookie "abc123" --ua "Mozilla/5.0..."

  # Offline cookie analysis
  python cf_cookie_inspector.py --cookie "abc123" --ua "Mozilla/5.0..."

  # View saved sessions
  python cf_cookie_inspector.py --sessions
"""
    )
    parser.add_argument("--url", help="Target URL to validate cookie against")
    parser.add_argument("--cookie", "-c", help="cf_clearance cookie value")
    parser.add_argument("--ua", "-u", help="User-Agent that was used during challenge solve")
    parser.add_argument("--sessions", action="store_true", help="List saved sessions from cf_session.py")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.sessions:
        sessions = list_sessions()
        if not sessions:
            print("No saved sessions found.")
            return
        now = time.time()
        print(f"{'Domain':<30} {'Status':<10} {'Remaining':<12} {'UA (first 50 chars)'}")
        print("-" * 95)
        for s in sessions:
            exp = s.get("expires_at", 0) - now
            status = "VALID" if exp > 0 else "EXPIRED"
            remaining = f"{int(exp // 60)}m {int(exp % 60)}s" if exp > 0 else "0s"
            ua_short = (s.get("user_agent", "")[:50] + "...") if len(s.get("user_agent", "")) > 50 else s.get("user_agent", "")
            print(f"{s.get('domain', '?'):<30} {status:<10} {remaining:<12} {ua_short}")
        return

    if not args.cookie:
        parser.print_help()
        sys.exit(1)

    cookie_val = args.cookie
    if cookie_val.startswith("cf_clearance="):
        cookie_val = cookie_val[len("cf_clearance="):]

    # Offline analysis
    analysis = analyze_cookie(cookie_val)

    if args.url and args.ua:
        # Online validation
        print(f"[*] Validating cookie against {args.url}...")
        validation = validate_cookie(args.url, cookie_val, args.ua)
        analysis["validation"] = validation
    elif args.url and not args.ua:
        print("[!] --ua is required for online validation (User-Agent must match the solver browser).", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print("=== Cookie Analysis ===")
        print(f"  Length        : {analysis['length']} chars")
        print(f"  Valid format  : {'Yes' if analysis['likely_valid_format'] else 'No (too short)'}")
        print(f"  Segments      : {analysis['segments']}")
        if analysis.get("base64_decodable"):
            print(f"  Base64 decode : Yes ({analysis['decoded_length']} bytes)")

        if "validation" in analysis:
            v = analysis["validation"]
            print("\n=== Online Validation ===")
            print(f"  Target       : {args.url}")
            print(f"  User-Agent   : {args.ua[:60]}...")
            print(f"  Status       : {v.get('status_code', '?')}")
            print(f"  Cookie valid : {'YES ✓' if v.get('valid') else 'NO ✗'}")
            print(f"  Is challenge : {v.get('is_challenge', '?')}")
            print(f"  Elapsed      : {v.get('elapsed', '?')}")
            if v.get("diagnosis"):
                print(f"  Diagnosis    : {v['diagnosis']}")
            if v.get("warning"):
                print(f"  Warning      : {v['warning']}")
            if v.get("cloudflare_headers"):
                print(f"  CF Headers   : {json.dumps(v['cloudflare_headers'], indent=2)}")


if __name__ == "__main__":
    main()
