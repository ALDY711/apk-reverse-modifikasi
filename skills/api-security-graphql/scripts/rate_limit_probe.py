#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API Rate Limiting & Resource Consumption Defensive Probe.

WHY THIS EXISTS
---------------
APIs lacking rate limiting (OWASP API4:2023 - Unrestricted Resource Consumption)
are susceptible to credential stuffing, brute force attacks, denial of service,
and resource exhaustion.

This tool sends a controlled sequence of test requests to verify whether the
target endpoint enforces rate limiting, emits standard RateLimit headers, or
returns HTTP 429 (Too Many Requests).

USAGE
-----
  # Probe rate limiting on an endpoint with 20 test requests
  python rate_limit_probe.py --url https://api.example.com/api/login --requests 20

  # Output structured JSON report
  python rate_limit_probe.py --url https://api.example.com/api/login --json

EXIT CODES
----------
  0 = Rate limiting is active (429 received or rate-limit headers present)
  1 = No rate limiting detected after threshold (potential risk)
  2 = Network error or invalid arguments
"""

import argparse
import json
import ssl
import sys
import time
import urllib.request
import urllib.error

RATE_LIMIT_HEADERS = [
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset"
]


def probe_endpoint(url, num_requests, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = []
    rate_limited = False
    headers_detected = {}

    for i in range(1, num_requests + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Security-Audit-Probe/1.0)",
                "Accept": "application/json, text/plain, */*"
            }
        )
        status_code = None
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status_code = resp.getcode()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            status_code = e.code
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
        except Exception as e:
            return None, f"Request failed on attempt {i}: {e}"

        # Check for rate limiting headers
        for r_hdr in RATE_LIMIT_HEADERS:
            if r_hdr in resp_headers:
                headers_detected[r_hdr] = resp_headers[r_hdr]

        results.append({
            "request_num": i,
            "status_code": status_code
        })

        if status_code == 429:
            rate_limited = True
            break

        time.sleep(0.05)  # Slight spacing to avoid TCP socket exhaustion

    summary = {
        "url": url,
        "total_requests_sent": len(results),
        "rate_limited_status_429": rate_limited,
        "rate_limit_headers_found": headers_detected,
        "enforces_rate_limiting": rate_limited or (len(headers_detected) > 0)
    }
    return summary, None


def main():
    parser = argparse.ArgumentParser(
        description="Probe API endpoint to verify rate limiting enforcement."
    )
    parser.add_argument("--url", required=True, help="Target API URL to probe.")
    parser.add_argument("--requests", type=int, default=15, help="Number of probe requests (default: 15).")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP request timeout in seconds (default: 5).")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    summary, err = probe_endpoint(args.url, args.requests, args.timeout)
    if err:
        sys.stderr.write(f"Error: {err}\n")
        return 2

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("=" * 72)
        print(" ⏱️  API RATE LIMITING DEFENSIVE PROBE")
        print("=" * 72)
        print(f" Target URL          : {summary['url']}")
        print(f" Requests Sent       : {summary['total_requests_sent']}")
        print(f" HTTP 429 Triggered  : {'[YES]' if summary['rate_limited_status_429'] else '[NO]'}")
        print(f" RateLimit Headers   : {list(summary['rate_limit_headers_found'].keys()) or '[NONE]'}")
        print("-" * 72)

        if summary["enforces_rate_limiting"]:
            print(" [OK] Endpoint enforces rate limiting or provides rate-limit headers.")
        else:
            print(" [ALERT] No rate limiting detected across probe burst.")
            print("         Verify whether gateway/WAF rate limits are properly configured.")
        print("=" * 72)

    return 0 if summary["enforces_rate_limiting"] else 1


if __name__ == "__main__":
    sys.exit(main())
