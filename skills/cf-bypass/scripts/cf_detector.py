#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare challenge and block detection script modeled after C:\\streming-anime\\backend\\src\\helpers\\getHTML.ts.

WHY THIS EXISTS
---------------
Before attempting expensive browser-based bypass routines, scrapers and reverse engineers
need a fast, zero-dependency way to evaluate whether a target response is:
  1. A normal page (not blocked).
  2. A Cloudflare challenge (IUAM / "Just a moment...", Turnstile, Captcha).
  3. A hard Cloudflare WAF block (Error 1020, 1015, 403 Forbidden).

This script performs heuristic analysis on HTML structure, response codes, and HTTP headers.

USAGE
-----
  # Check a live URL
  python cf_detector.py --url https://example.com

  # Inspect a downloaded HTML file
  python cf_detector.py --file response.html

  # JSON output for automated scripting
  python cf_detector.py --url https://example.com --json
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error


CHALLENGE_INDICATORS = [
    "Just a moment...",
    "Tunggu sebentar...",
    "Attention Required!",
    "cf-browser-verification",
    "cf-challenge-running",
    "Sorry, you have been blocked",
    "cf-turnstile",
    "Enable JavaScript and cookies to continue",
    "cf_chl_opt",
    "challenge-error-title",
    "challenges.cloudflare.com",
    "/cdn-cgi/challenge-platform/",
]

TITLE_CHALLENGE_RE = re.compile(
    r"<title\b[^>]*>(.*?)(just a moment|attention required|tunggu sebentar|cloudflare)(.*?)</title>",
    re.IGNORECASE | re.DOTALL
)


def analyze_html(html: str) -> dict:
    """Analyze HTML content for Cloudflare block and challenge signatures."""
    if not html or not html.strip():
        return {
            "blocked": True,
            "type": "EMPTY_RESPONSE",
            "reason": "HTML response is empty or whitespace only",
            "confidence": 1.0,
            "size_bytes": 0
        }

    size = len(html.encode("utf-8", errors="replace"))
    lower_html = html.lower()

    # Rule from getHTML.ts: Challenge pages are almost always compact (< 30KB).
    # If > 30KB and no challenge title, it is typically NOT a block.
    has_title_challenge = bool(TITLE_CHALLENGE_RE.search(html))

    if size > 30000 and not has_title_challenge:
        return {
            "blocked": False,
            "type": "NORMAL_CONTENT",
            "reason": f"Content size ({size} bytes) exceeds 30KB threshold and contains no challenge title",
            "confidence": 0.95,
            "size_bytes": size
        }

    # Match challenge indicators
    matched_indicators = [ind for ind in CHALLENGE_INDICATORS if ind.lower() in lower_html]

    if matched_indicators or has_title_challenge:
        challenge_type = "IUAM_OR_TURNSTILE"
        if "cf-turnstile" in lower_html or "challenges.cloudflare.com" in lower_html:
            challenge_type = "TURNSTILE_CAPTCHA"
        elif "sorry, you have been blocked" in lower_html or "1020" in lower_html:
            challenge_type = "HARD_WAF_BLOCK"

        return {
            "blocked": True,
            "type": challenge_type,
            "reason": "Matched Cloudflare challenge indicators",
            "indicators": matched_indicators,
            "title_challenge": has_title_challenge,
            "confidence": 0.99,
            "size_bytes": size
        }

    return {
        "blocked": False,
        "type": "NORMAL_CONTENT",
        "reason": "No Cloudflare challenge signatures detected",
        "confidence": 0.85,
        "size_bytes": size
    }


def check_url(url: str, user_agent: str = None) -> dict:
    """Fetch URL and perform Cloudflare header and body inspection."""
    ua = user_agent or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    )
    req = urllib.request.Request(url, headers={"User-Agent": ua})

    status_code = 200
    headers = {}
    body = ""

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            status_code = res.status
            headers = dict(res.headers)
            body = res.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        status_code = err.code
        headers = dict(err.headers)
        try:
            body = err.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
    except Exception as exc:
        return {
            "url": url,
            "error": str(exc),
            "blocked": True,
            "type": "NETWORK_ERROR"
        }

    cf_headers = {k: v for k, v in headers.items() if k.lower().startswith("cf-") or k.lower() == "server"}
    analysis = analyze_html(body)
    analysis["url"] = url
    analysis["status_code"] = status_code
    analysis["cloudflare_headers"] = cf_headers
    analysis["behind_cloudflare"] = "cf-ray" in [k.lower() for k in headers] or "cloudflare" in headers.get("server", "").lower()

    return analysis


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Challenge & Block Detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target URL to fetch and evaluate")
    group.add_argument("--file", "-f", help="Local HTML file to inspect")
    parser.add_argument("--ua", help="Custom User-Agent string")
    parser.add_argument("--json", action="store_true", help="Print result as JSON")

    args = parser.parse_args()

    if args.url:
        result = check_url(args.url, args.ua)
    else:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            result = analyze_html(content)
            result["file"] = args.file
        except Exception as e:
            result = {"file": args.file, "error": str(e), "blocked": True}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("=== Cloudflare Detection Result ===")
        print(f"Target      : {result.get('url') or result.get('file')}")
        print(f"Blocked     : {'YES [!] Cloudflare active' if result.get('blocked') else 'NO [OK]'}")
        print(f"Type        : {result.get('type')}")
        print(f"Reason      : {result.get('reason')}")
        if result.get("indicators"):
            print(f"Indicators  : {', '.join(result['indicators'])}")
        if result.get("cloudflare_headers"):
            print(f"CF Headers  : {result['cloudflare_headers']}")


if __name__ == "__main__":
    main()
