#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze HTTP Archive (.har) files from browser DevTools for Web Reverse Engineering.

WHY THIS EXISTS
---------------
During web application reverse engineering, browser DevTools Network tab allows exporting
all traffic as a HAR (HTTP Archive) file. HAR files contain complete request/response flows,
including headers, cookies, API payloads, response bodies, and timing.

This tool:
  1. Parses HAR files exported from Chrome, Firefox, Safari, or Edge.
  2. Filters and catalogs REST/GraphQL/JSON API endpoints automatically.
  3. Identifies authentication tokens (JWT, Bearer, API Keys, custom sign headers).
  4. Generates copy-paste ready `curl` commands and Python `requests` snippets.
  5. Exports a clean markdown or JSON summary of endpoints and parameter schemas.

USAGE
-----
  # Analyze HAR file and list all detected API calls
  python har_analyzer.py --file network.har

  # Filter specific host or endpoint keyword
  python har_analyzer.py --file network.har --filter "api"

  # Generate replay cURL commands for matched endpoints
  python har_analyzer.py --file network.har --export-curl --out ./curls.sh

  # Output full analysis to JSON
  python har_analyzer.py --file network.har --json --out report.json
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse


def parse_har(file_path: str, filter_keyword: str = None) -> list:
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Error parsing JSON in HAR file: {e}", file=sys.stderr)
        sys.exit(1)

    entries = data.get("log", {}).get("entries", [])
    results = []

    for entry in entries:
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")

        if filter_keyword and filter_keyword.lower() not in url.lower():
            continue

        mime_type = res.get("content", {}).get("mimeType", "")
        status = res.get("status", 0)

        # Headers analysis
        headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
        interesting_headers = {}
        for k, v in headers.items():
            kl = k.lower()
            if any(term in kl for term in ["auth", "token", "sign", "key", "secret", "csrf", "cookie", "x-"]):
                interesting_headers[k] = v

        results.append({
            "method": method,
            "url": url,
            "status": status,
            "mime_type": mime_type,
            "headers": interesting_headers,
            "post_data": req.get("postData", {}).get("text", "") if "postData" in req else None,
            "response_size": res.get("content", {}).get("size", 0)
        })

    return results


def to_curl(item: dict) -> str:
    parts = ["curl", "-X", item["method"], f'"{item["url"]}"']
    for k, v in item.get("headers", {}).items():
        if k.lower() not in ["cookie", "host"]:
            parts.append(f'-H "{k}: {v}"')
    if item.get("post_data"):
        data_clean = item["post_data"].replace('"', '\\"')
        parts.append(f'--data "{data_clean}"')
    return " \\\n  ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Analyze DevTools HAR network traces.")
    parser.add_argument("--file", "-f", required=True, help="Path to .har file")
    parser.add_argument("--filter", help="Filter URLs matching substring")
    parser.add_argument("--export-curl", action="store_true", help="Generate cURL replay commands")
    parser.add_argument("--json", action="store_true", help="Output raw JSON analysis")
    parser.add_argument("--out", "-o", help="Output file path")

    args = parser.parse_args()
    results = parse_har(args.file, args.filter)

    if args.json:
        out_str = json.dumps(results, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_str)
            print(f"[+] Report saved to {args.out}")
        else:
            print(out_str)
        return

    if args.export_curl:
        lines = ["#!/usr/bin/env bash\n"]
        for idx, item in enumerate(results, 1):
            lines.append(f"# [{idx}] {item['method']} {item['url']} (Status: {item['status']})")
            lines.append(to_curl(item))
            lines.append("\n")
        out_str = "\n".join(lines)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_str)
            print(f"[+] Replay cURL scripts saved to {args.out}")
        else:
            print(out_str)
        return

    print(f"=== HAR Trace Analysis: {len(results)} requests identified ===")
    for idx, item in enumerate(results, 1):
        print(f"\n[{idx}] {item['method']} {item['url']} -> {item['status']} ({item['mime_type']})")
        if item["headers"]:
            print("  Interesting Headers:")
            for hk, hv in item["headers"].items():
                val_disp = (hv[:60] + "...") if len(hv) > 60 else hv
                print(f"    - {hk}: {val_disp}")
        if item.get("post_data"):
            pd = item["post_data"]
            pd_disp = (pd[:120] + "...") if len(pd) > 120 else pd
            print(f"  Payload: {pd_disp}")


if __name__ == "__main__":
    main()
