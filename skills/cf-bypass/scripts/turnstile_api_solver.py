#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turnstile & Cloudflare Challenge External API Solver Bridge (CapSolver / 2Captcha / Anti-Captcha).

WHY THIS EXISTS
---------------
While headless browser automation (Puppeteer Real Browser / Cantarella) can solve >90% of
Turnstile challenges locally, extreme Enterprise Cloudflare Bot Management deployments
may flag datacenter IP ranges or apply high-frequency IP-level rate limits.

Furthermore, on low-resource servers (e.g. 512MB–1GB RAM micro-VPS), running Chromium
instances is infeasible.

This tool provides a lightweight, pure-HTTP bridge to solve Cloudflare Turnstile and
Challenge 5s pages via commercial solving APIs (CapSolver, 2Captcha, Anti-Captcha),
returning the `cf-turnstile-response` token or `cf_clearance` cookie without spawning any
local browser processes!

USAGE
-----
  # Solve Turnstile using CapSolver API key
  python turnstile_api_solver.py --provider capsolver --api-key "CAP-XXXXX" --url "https://target.com/login" --sitekey "0x4AAAAAAABcd12345"

  # Solve Turnstile using 2Captcha
  python turnstile_api_solver.py --provider 2captcha --api-key "2cap_key_xxx" --url "https://target.com" --sitekey "0x4AAAAAAABcd12345"

  # Solve Cloudflare 5s Challenge / IUAM task
  python turnstile_api_solver.py --provider capsolver --api-key "CAP-XXXXX" --task-type cf-challenge --url "https://target.com"

  # Output structured JSON result
  python turnstile_api_solver.py --provider capsolver --api-key "CAP-XXXXX" --url "https://target.com" --sitekey "0x4AAAAAA..." --json

EXIT CODES
----------
  0 = challenge solved, token/cookie returned
  1 = solving error or timeout
  2 = argument or configuration error
"""

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path


def solve_capsolver(api_key: str, url: str, sitekey: str | None, task_type: str = "turnstile", proxy: str | None = None) -> dict:
    """Solve Turnstile or Cloudflare challenge using CapSolver API."""
    create_task_url = "https://api.capsolver.com/createTask"
    get_result_url = "https://api.capsolver.com/getTaskResult"

    if task_type == "turnstile":
        task_payload = {
            "type": "AntiTurnstileTaskProxyLess" if not proxy else "AntiTurnstileTask",
            "websiteURL": url,
            "websiteKey": sitekey,
        }
    else:
        task_payload = {
            "type": "AntiCloudflareTask",
            "websiteURL": url,
        }

    if proxy:
        task_payload["proxy"] = proxy

    payload = {
        "clientKey": api_key,
        "task": task_payload
    }

    req = urllib.request.Request(
        create_task_url,
        data=json.dumps(payload).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode('utf-8'))

    if res.get("errorId", 0) != 0:
        raise ValueError(f"CapSolver createTask error: {res.get('errorDescription', 'Unknown')}")

    task_id = res.get("taskId")
    if not task_id:
        # Immediate result
        solution = res.get("solution", {})
        return solution

    # Poll for result
    poll_payload = {"clientKey": api_key, "taskId": task_id}
    start_time = time.time()
    while time.time() - start_time < 60:
        time.sleep(2)
        poll_req = urllib.request.Request(
            get_result_url,
            data=json.dumps(poll_payload).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(poll_req, timeout=15) as poll_resp:
            poll_res = json.loads(poll_resp.read().decode('utf-8'))

        status = poll_res.get("status")
        if status == "ready":
            return poll_res.get("solution", {})
        elif status == "failed":
            raise ValueError(f"CapSolver task failed: {poll_res.get('errorDescription')}")

    raise TimeoutError("CapSolver task polling timed out after 60 seconds")


def solve_2captcha(api_key: str, url: str, sitekey: str) -> dict:
    """Solve Turnstile using 2Captcha API."""
    in_url = f"https://2captcha.com/in.php?key={api_key}&method=turnstile&sitekey={sitekey}&pageurl={url}&json=1"
    req = urllib.request.Request(in_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode('utf-8'))

    if res.get("status") != 1:
        raise ValueError(f"2Captcha in.php error: {res.get('request')}")

    request_id = res.get("request")
    res_url = f"https://2captcha.com/res.php?key={api_key}&action=get&id={request_id}&json=1"

    start_time = time.time()
    time.sleep(5)
    while time.time() - start_time < 60:
        time.sleep(3)
        poll_req = urllib.request.Request(res_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(poll_req, timeout=15) as poll_resp:
            poll_res = json.loads(poll_resp.read().decode('utf-8'))

        if poll_res.get("status") == 1:
            token = poll_res.get("request")
            return {"token": token, "cf-turnstile-response": token}
        elif poll_res.get("request") != "CAPCHA_NOT_READY":
            raise ValueError(f"2Captcha res.php error: {poll_res.get('request')}")

    raise TimeoutError("2Captcha task polling timed out after 60 seconds")


def main():
    parser = argparse.ArgumentParser(
        description="External CAPTCHA Solver Bridge for Cloudflare Turnstile & IUAM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--provider", "-p", choices=["capsolver", "2captcha"], default="capsolver", help="Solver provider API")
    parser.add_argument("--api-key", "-k", required=True, help="Provider API Key")
    parser.add_argument("--url", "-u", required=True, help="Target page URL")
    parser.add_argument("--sitekey", "-s", help="Turnstile sitekey (e.g. 0x4AAAAAA...)")
    parser.add_argument("--task-type", "-t", choices=["turnstile", "cf-challenge"], default="turnstile", help="Challenge task type")
    parser.add_argument("--proxy", help="Optional proxy for task execution (e.g. http://user:pass@host:port)")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")

    args = parser.parse_args()

    try:
        if args.provider == "capsolver":
            solution = solve_capsolver(args.api_key, args.url, args.sitekey, args.task_type, args.proxy)
        elif args.provider == "2captcha":
            if not args.sitekey:
                print("[!] Error: --sitekey is required for 2captcha provider.", file=sys.stderr)
                sys.exit(2)
            solution = solve_2captcha(args.api_key, args.url, args.sitekey)
        else:
            print("[!] Unsupported provider.", file=sys.stderr)
            sys.exit(2)

        if args.json:
            print(json.dumps(solution, indent=2))
        else:
            print("[+] Turnstile / Cloudflare Challenge Solved Successfully!")
            token = solution.get("token") or solution.get("cf-turnstile-response") or solution.get("cf_clearance")
            print(f"[*] Solution Token: {token}")
            if "userAgent" in solution:
                print(f"[*] Matched User-Agent: {solution['userAgent']}")
            if "cookies" in solution:
                print(f"[*] Cookies: {solution['cookies']}")
            print("\n[+] Injection Snippet for DevTools/Puppeteer:")
            print(f'    document.querySelector("[name=cf-turnstile-response]").value = "{token}";')
            print('    if (typeof window.tsCallback === "function") window.tsCallback();')
        sys.exit(0)

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"[!] Solver Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
