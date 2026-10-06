#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cantarella Bypass Engine API client.

Communicates with the Cantarella Bypass sidecar service (.cf-bypass) to solve
Cloudflare IUAM and Turnstile challenges via its POST /cloudflare API endpoint.

Modeled after the integration pattern in:
  C:\\streming-anime\\backend\\src\\helpers\\getHTML.ts (Step 6 — Cantarella Bypass)

The pattern:
  1. POST to Cantarella server with { mode: "iuam", domain: "https://..." }
  2. Receive { cf_clearance, user_agent, elapsed, html }
  3. If html is clean → use directly
  4. If html still blocked → replay with got-scraping using cf_clearance + user_agent

USAGE
-----
  # Solve IUAM and print result
  python cf_cantarella_client.py iuam --domain "https://target.com"

  # Solve IUAM and fetch page with the clearance cookie
  python cf_cantarella_client.py iuam --domain "https://target.com" --fetch --out page.html

  # Solve Turnstile and get token
  python cf_cantarella_client.py turnstile --domain "https://target.com" --sitekey "0x4AAAAAA..."

  # Use custom server address
  python cf_cantarella_client.py iuam --domain "https://target.com" --server "http://vps:8742"
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

DEFAULT_SERVER = os.environ.get("CF_BYPASS_URL", "http://localhost:8742")
DEFAULT_TIMEOUT = 90  # Cantarella may take up to 60s for hard challenges


def solve_iuam(domain: str, server: str, auth_token: str = None,
               proxy_user: str = None, proxy_pass: str = None,
               ttl: int = None) -> dict:
    """Solve Cloudflare IUAM challenge via Cantarella API."""
    payload = {
        "mode": "iuam",
        "domain": domain,
        "nocache": int(time.time() * 1000)
    }
    if auth_token:
        payload["authToken"] = auth_token
    if proxy_user and proxy_pass:
        payload["proxy"] = {"username": proxy_user, "password": proxy_pass}
    if ttl:
        payload["ttl"] = ttl

    return _call_api(server, payload)


def solve_turnstile(domain: str, site_key: str, server: str,
                    auth_token: str = None,
                    proxy_user: str = None, proxy_pass: str = None) -> dict:
    """Solve Cloudflare Turnstile CAPTCHA via Cantarella API."""
    payload = {
        "mode": "turnstile",
        "domain": domain,
        "siteKey": site_key
    }
    if auth_token:
        payload["authToken"] = auth_token
    if proxy_user and proxy_pass:
        payload["proxy"] = {"username": proxy_user, "password": proxy_pass}

    return _call_api(server, payload)


def _call_api(server: str, payload: dict) -> dict:
    """Make POST request to Cantarella /cloudflare endpoint."""
    url = f"{server.rstrip('/')}/cloudflare"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    print(f"[Cantarella] POST {url}")
    print(f"[Cantarella] Payload: {json.dumps(payload, indent=2)}")
    start = time.time()

    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as res:
            body = res.read().decode("utf-8", errors="replace")
            result = json.loads(body)
            elapsed = time.time() - start
            print(f"[Cantarella] Response received in {elapsed:.2f}s")
            return result
    except urllib.error.HTTPError as err:
        body = ""
        try:
            body = err.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {
            "error": True,
            "status": err.code,
            "message": body or str(err),
            "elapsed": f"{time.time() - start:.2f}s"
        }
    except Exception as exc:
        return {
            "error": True,
            "message": str(exc),
            "elapsed": f"{time.time() - start:.2f}s"
        }


def fetch_with_clearance(url: str, cf_clearance: str, user_agent: str) -> str:
    """Fetch URL using the solved cf_clearance cookie and matching User-Agent.

    WARNING: This uses Python's urllib which has a different TLS fingerprint than Chrome.
    For production use, prefer got-scraping (Node.js) or curl_cffi (Python) which can
    impersonate Chrome's JA3/JA4 fingerprint. This function is for quick testing only.
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": user_agent,
        "Cookie": f"cf_clearance={cf_clearance}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return res.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        print(f"[!] HTTP {err.code} — TLS fingerprint mismatch? Use got-scraping instead.", file=sys.stderr)
        try:
            return err.read().decode("utf-8", errors="replace")
        except Exception:
            return ""


def main():
    parser = argparse.ArgumentParser(
        description="Cantarella Bypass Engine API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Solve IUAM
  python cf_cantarella_client.py iuam --domain "https://example.com"

  # Solve Turnstile
  python cf_cantarella_client.py turnstile --domain "https://example.com" --sitekey "0x4AAA..."

  # Solve and immediately fetch page
  python cf_cantarella_client.py iuam --domain "https://example.com" --fetch --out page.html

Environment Variables:
  CF_BYPASS_URL    Default server URL (default: http://localhost:8742)
  CF_AUTH_TOKEN    Auth token for the Cantarella server
"""
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # IUAM subcommand
    p_iuam = subparsers.add_parser("iuam", help="Solve IUAM (I'm Under Attack Mode) challenge")
    p_iuam.add_argument("--domain", "-d", required=True, help="Full URL of target domain (https://...)")
    p_iuam.add_argument("--server", "-s", default=DEFAULT_SERVER, help="Cantarella server URL")
    p_iuam.add_argument("--auth", help="Auth token for Cantarella server")
    p_iuam.add_argument("--proxy-user", help="Proxy username")
    p_iuam.add_argument("--proxy-pass", help="Proxy password")
    p_iuam.add_argument("--ttl", type=int, help="Cache TTL in milliseconds")
    p_iuam.add_argument("--fetch", action="store_true", help="After solving, fetch the page with clearance cookie")
    p_iuam.add_argument("--out", "-o", help="Output file for fetched content")
    p_iuam.add_argument("--json", action="store_true", help="Output raw JSON result")

    # Turnstile subcommand
    p_ts = subparsers.add_parser("turnstile", help="Solve Turnstile CAPTCHA challenge")
    p_ts.add_argument("--domain", "-d", required=True, help="Full URL of target domain")
    p_ts.add_argument("--sitekey", "-k", required=True, help="Turnstile siteKey (0x4AAAAAA...)")
    p_ts.add_argument("--server", "-s", default=DEFAULT_SERVER, help="Cantarella server URL")
    p_ts.add_argument("--auth", help="Auth token for Cantarella server")
    p_ts.add_argument("--proxy-user", help="Proxy username")
    p_ts.add_argument("--proxy-pass", help="Proxy password")
    p_ts.add_argument("--json", action="store_true", help="Output raw JSON result")

    args = parser.parse_args()
    auth_token = args.auth or os.environ.get("CF_AUTH_TOKEN")

    if args.mode == "iuam":
        result = solve_iuam(
            domain=args.domain,
            server=args.server,
            auth_token=auth_token,
            proxy_user=getattr(args, "proxy_user", None),
            proxy_pass=getattr(args, "proxy_pass", None),
            ttl=getattr(args, "ttl", None)
        )

        if args.json:
            print(json.dumps(result, indent=2))
            return

        if result.get("error"):
            print(f"[!] FAILED: {result.get('message')}", file=sys.stderr)
            sys.exit(1)

        print(f"[+] cf_clearance : {result.get('cf_clearance', 'N/A')}")
        print(f"[+] user_agent   : {result.get('user_agent', 'N/A')}")
        print(f"[+] elapsed      : {result.get('elapsed', 'N/A')}")
        print(f"[+] cached       : {result.get('cached', False)}")
        print(f"[+] html size    : {len(result.get('html', ''))} bytes")

        if args.fetch and result.get("cf_clearance"):
            print(f"\n[Fetch] Fetching {args.domain} with clearance cookie...")
            html = fetch_with_clearance(args.domain, result["cf_clearance"], result.get("user_agent", ""))
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[+] Page saved to {args.out} ({len(html)} bytes)")
            else:
                print(f"[+] Fetched {len(html)} bytes")
                if len(html) < 2000:
                    print(html)

    elif args.mode == "turnstile":
        result = solve_turnstile(
            domain=args.domain,
            site_key=args.sitekey,
            server=args.server,
            auth_token=auth_token,
            proxy_user=getattr(args, "proxy_user", None),
            proxy_pass=getattr(args, "proxy_pass", None)
        )

        if args.json:
            print(json.dumps(result, indent=2))
            return

        if result.get("error") or result.get("code", 200) != 200:
            print(f"[!] FAILED: {result.get('message')}", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Turnstile Token: {result.get('token', 'N/A')}")
        print(f"[+] elapsed        : {result.get('elapsed', 'N/A')}")


if __name__ == "__main__":
    main()
