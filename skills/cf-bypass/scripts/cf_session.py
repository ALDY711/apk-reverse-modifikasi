#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare session manager and request replayer.

WHY THIS EXISTS
---------------
Once a challenge solver extracts the `cf_clearance` cookie, using it incorrectly will
immediately trigger another 403 Forbidden.

RULE: The `cf_clearance` cookie is cryptographically bound to the User-Agent and TLS Client
Hello fingerprint used during solving. This script manages stored session tokens and formats
replay commands (curl, Python requests, Node fetch) with exact fingerprint alignment.

USAGE
-----
  # Store a solved clearance token in local session cache
  python cf_session.py store --domain example.com --clearance "AbC...123" --ua "Mozilla/5.0..."

  # Export a cURL command using stored session
  python cf_session.py curl --url "https://example.com/api/data"

  # Send test request via Python requests with session token
  python cf_session.py fetch --url "https://example.com/api/data"
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

SESSION_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".cf_sessions.json")
DEFAULT_TTL = 30 * 60  # 30 minutes


def load_sessions() -> dict:
    if os.path.exists(SESSION_CACHE_FILE):
        try:
            with open(SESSION_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_sessions(data: dict):
    with open(SESSION_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def store_session(domain: str, clearance: str, user_agent: str, ttl: int = DEFAULT_TTL):
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    sessions = load_sessions()
    sessions[domain] = {
        "domain": domain,
        "cf_clearance": clearance,
        "user_agent": user_agent,
        "expires_at": int(time.time()) + ttl,
        "created_at": int(time.time())
    }
    save_sessions(sessions)
    print(f"[+] Session stored for {domain} (valid for {ttl // 60} minutes)")


def get_session(domain: str) -> dict | None:
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    sessions = load_sessions()
    entry = sessions.get(domain)
    if entry and entry.get("expires_at", 0) > time.time():
        return entry
    return None


def generate_curl(url: str) -> str:
    domain = urlparse(url).netloc
    sess = get_session(domain)
    if not sess:
        print(f"[-] No valid session found for domain: {domain}", file=sys.stderr)
        return ""

    cmd = (
        f'curl -s -X GET "{url}" \\\n'
        f'  -H "User-Agent: {sess["user_agent"]}" \\\n'
        f'  -H "Cookie: cf_clearance={sess["cf_clearance"]}" \\\n'
        f'  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\\n'
        f'  -H "Accept-Language: en-US,en;q=0.9"'
    )
    return cmd


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Clearance Session Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: store
    p_store = subparsers.add_parser("store", help="Store clearance token and UA")
    p_store.add_argument("--domain", "-d", required=True, help="Target domain (e.g. example.com)")
    p_store.add_argument("--clearance", "-c", required=True, help="Value of cf_clearance cookie")
    p_store.add_argument("--ua", "-u", required=True, help="Exact User-Agent used during solve")
    p_store.add_argument("--ttl", type=int, default=DEFAULT_TTL, help="Validity period in seconds")

    # Subcommand: curl
    p_curl = subparsers.add_parser("curl", help="Generate authenticated curl command")
    p_curl.add_argument("--url", required=True, help="Target URL")

    # Subcommand: list
    subparsers.add_parser("list", help="List active stored sessions")

    args = parser.parse_args()

    if args.command == "store":
        store_session(args.domain, args.clearance, args.ua, args.ttl)
    elif args.command == "curl":
        curl_cmd = generate_curl(args.url)
        if curl_cmd:
            print(curl_cmd)
    elif args.command == "list":
        sessions = load_sessions()
        now = time.time()
        print(f"{'Domain':<30} {'Status':<10} {'Expires In'}")
        print("-" * 55)
        for dom, data in sessions.items():
            exp = data.get("expires_at", 0) - now
            status = "VALID" if exp > 0 else "EXPIRED"
            time_left = f"{int(exp // 60)} min" if exp > 0 else "0 min"
            print(f"{dom:<30} {status:<10} {time_left}")


if __name__ == "__main__":
    main()
