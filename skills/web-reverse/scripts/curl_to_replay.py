#!/usr/bin/env python3
"""Convert cURL command strings or raw HTTP requests into production-ready Python replay scripts.

Supports generating replay scripts with `curl_cffi` (impersonating modern Chrome/Safari TLS JA3/JA4 fingerprints),
`requests`, or `httpx`. Automatically isolates dynamic headers (signatures, timestamps, nonces, cookies)
into configurable parameter generators.

Usage:
    python curl_to_replay.py --curl "curl 'https://api.example.com/data' -H 'X-Sign: 1234'"
    python curl_to_replay.py --file request.curl --output replay.py --library curl_cffi --impersonate chrome120
    python curl_to_replay.py --help
"""

import argparse
import json
import re
import shlex
import sys
from urllib.parse import urlparse, parse_qs, unquote


def parse_curl_command(curl_str: str) -> dict:
    """Parse a curl command line string into a structured dictionary."""
    # Clean up multi-line continuations (both bash \ and powershell `)
    cleaned = curl_str.strip()
    cleaned = re.sub(r'\\\r?\n\s*', ' ', cleaned)
    cleaned = re.sub(r'`\r?\n\s*', ' ', cleaned)
    cleaned = re.sub(r'\^\r?\n\s*', ' ', cleaned)

    try:
        tokens = shlex.split(cleaned, posix=True)
    except Exception:
        # Fallback to simple split if shlex fails on Windows quotes
        tokens = cleaned.split()

    if not tokens:
        raise ValueError("Empty curl command provided.")

    # Remove leading 'curl' if present
    if tokens[0].lower() in ('curl', 'curl.exe'):
        tokens = tokens[1:]

    method = "GET"
    url = ""
    headers = {}
    data = None
    cookies = {}

    idx = 0
    while idx < len(tokens):
        token = tokens[idx]

        if token in ('-X', '--request') and idx + 1 < len(tokens):
            method = tokens[idx + 1].upper()
            idx += 2
        elif token in ('-H', '--header') and idx + 1 < len(tokens):
            header_line = tokens[idx + 1]
            if ':' in header_line:
                k, v = header_line.split(':', 1)
                headers[k.strip()] = v.strip()
            idx += 2
        elif token in ('-b', '--cookie') and idx + 1 < len(tokens):
            cookie_str = tokens[idx + 1]
            for pair in cookie_str.split(';'):
                if '=' in pair:
                    ck, cv = pair.strip().split('=', 1)
                    cookies[ck.strip()] = cv.strip()
            idx += 2
        elif token in ('-d', '--data', '--data-raw', '--data-binary', '--data-ascii') and idx + 1 < len(tokens):
            data = tokens[idx + 1]
            if method == "GET":
                method = "POST"
            idx += 2
        elif token.startswith('http://') or token.startswith('https://'):
            url = token
            idx += 1
        elif token.startswith('-'):
            # Other curl flag, skip argument if takes one
            if token in ('-u', '--user', '-A', '--user-agent', '-e', '--referer', '-o', '--output', '--proxy') and idx + 1 < len(tokens):
                idx += 2
            else:
                idx += 1
        else:
            if not url and ('/' in token or '.' in token):
                url = token
            idx += 1

    # Extract cookies from header if present and not in cookie list
    if 'Cookie' in headers and not cookies:
        for pair in headers['Cookie'].split(';'):
            if '=' in pair:
                ck, cv = pair.strip().split('=', 1)
                cookies[ck.strip()] = cv.strip()

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "data": data
    }


def identify_dynamic_fields(headers: dict) -> tuple[dict, dict]:
    """Separate static headers from likely dynamic security/signature headers."""
    dynamic_keys = {
        'timestamp', 'time', 't', 'ts',
        'sign', 'signature', 'x-sign', 'x-signature', 'x-req-sign',
        'nonce', 'x-nonce',
        'authorization', 'token', 'x-token', 'auth-token',
        'device-id', 'deviceid', 'x-device-id',
        'trace-id', 'request-id', 'x-request-id'
    }

    static_headers = {}
    dynamic_headers = {}

    for k, v in headers.items():
        if k.lower() in dynamic_keys or any(dk in k.lower() for dk in ['sign', 'nonce', 'token']):
            dynamic_headers[k] = v
        else:
            static_headers[k] = v

    return static_headers, dynamic_headers


def generate_python_script(parsed: dict, library: str = "curl_cffi", impersonate: str = "chrome120") -> str:
    """Generate clean, modular Python replay code."""
    method = parsed["method"]
    url = parsed["url"]
    headers = parsed["headers"]
    cookies = parsed["cookies"]
    raw_data = parsed["data"]

    static_headers, dynamic_headers = identify_dynamic_fields(headers)

    # Try parsing JSON data
    is_json = False
    json_data = None
    if raw_data:
        try:
            json_data = json.loads(raw_data)
            is_json = True
        except Exception:
            is_json = False

    lines = []
    lines.append("#!/usr/bin/env python3")
    lines.append('"""Auto-generated Web API Replay Script.')
    lines.append(f"Target URL: {url}")
    lines.append(f"Library: {library} (Impersonation: {impersonate if library == 'curl_cffi' else 'N/A'})")
    lines.append('"""')
    lines.append("import json")
    lines.append("import time")

    if library == "curl_cffi":
        lines.append("from curl_cffi import requests")
    elif library == "httpx":
        lines.append("import httpx")
    else:
        lines.append("import requests")

    lines.append("")
    lines.append("# Target Endpoint Configuration")
    lines.append(f'URL = "{url}"')
    lines.append("")

    lines.append("# Static Request Headers")
    lines.append("STATIC_HEADERS = " + json.dumps(static_headers, indent=4))
    lines.append("")

    if dynamic_headers:
        lines.append("def generate_dynamic_headers() -> dict:")
        lines.append('    """Compute dynamic signature headers (timestamps, nonces, hash tokens)."""')
        lines.append("    # Current millisecond or second timestamp")
        lines.append("    current_ts = int(time.time() * 1000)")
        lines.append("    dynamic = {}")
        for k, v in dynamic_headers.items():
            lines.append(f'    # Original value: {v}')
            lines.append(f'    dynamic["{k}"] = "{v}"  # TODO: Replace with dynamic signature algorithm')
        lines.append("    return dynamic")
        lines.append("")

    if cookies:
        lines.append("# Cookies (Session / Security Tokens)")
        lines.append("COOKIES = " + json.dumps(cookies, indent=4))
        lines.append("")

    if raw_data:
        if is_json:
            lines.append("# Payload (JSON)")
            lines.append("PAYLOAD = " + json.dumps(json_data, indent=4))
        else:
            lines.append("# Payload (Raw Data / URL Encoded)")
            lines.append(f'PAYLOAD = """{raw_data}"""')
        lines.append("")

    lines.append("def send_request():")
    lines.append('    """Execute the HTTP request with configured headers and payload."""')
    lines.append("    headers = STATIC_HEADERS.copy()")
    if dynamic_headers:
        lines.append("    headers.update(generate_dynamic_headers())")

    req_args = [f'"{method}"', "URL", "headers=headers"]
    if cookies:
        req_args.append("cookies=COOKIES")

    if raw_data:
        if is_json:
            req_args.append("json=PAYLOAD")
        else:
            req_args.append("data=PAYLOAD")

    if library == "curl_cffi":
        req_args.append(f'impersonate="{impersonate}"')

    lines.append(f"    print(f'[*] Sending {method} request to: {{URL}}')")
    if library == "httpx":
        lines.append("    with httpx.Client() as client:")
        lines.append(f"        response = client.request({', '.join(req_args)})")
    elif library == "curl_cffi":
        lines.append(f"    response = requests.request({', '.join(req_args)})")
    else:
        lines.append(f"    response = requests.request({', '.join(req_args)})")

    lines.append("    print(f'[+] Status Code: {response.status_code}')")
    lines.append("    try:")
    lines.append("        res_json = response.json()")
    lines.append("        print('[+] Response JSON:')")
    lines.append("        print(json.dumps(res_json, indent=2))")
    lines.append("        return res_json")
    lines.append("    except Exception:")
    lines.append("        print('[+] Response Text (first 500 chars):')")
    lines.append("        print(response.text[:500])")
    lines.append("        return response.text")
    lines.append("")

    lines.append('if __name__ == "__main__":')
    lines.append("    send_request()")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Convert cURL command strings into modular Python replay scripts."
    )
    parser.add_argument("--curl", type=str, help="Raw cURL command string")
    parser.add_argument("--file", type=str, help="Path to file containing cURL command")
    parser.add_argument("--output", type=str, help="Output path for generated .py script (default: stdout)")
    parser.add_argument("--library", choices=["curl_cffi", "requests", "httpx"], default="curl_cffi",
                        help="Target HTTP library for replay script (default: curl_cffi)")
    parser.add_argument("--impersonate", type=str, default="chrome120",
                        help="TLS browser profile for curl_cffi (default: chrome120)")

    args = parser.parse_args()

    curl_content = ""
    if args.curl:
        curl_content = args.curl
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                curl_content = f.read()
        except Exception as e:
            sys.exit(f"[-] Error reading file {args.file}: {e}")
    else:
        # Check stdin
        if not sys.stdin.isatty():
            curl_content = sys.stdin.read()
        else:
            parser.print_help()
            sys.exit(1)

    try:
        parsed = parse_curl_command(curl_content)
        script_code = generate_python_script(parsed, library=args.library, impersonate=args.impersonate)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(script_code)
            print(f"[+] Replay script successfully saved to: {args.output}")
        else:
            print(script_code)
    except Exception as e:
        sys.exit(f"[-] Failed to convert cURL: {e}")


if __name__ == "__main__":
    main()
