#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate Userscripts (.user.js) and run a local interceptor proxy to modify live web pages and APIs.

WHY THIS EXISTS
---------------
Once reverse engineering identifies the client-side JavaScript function or DOM element to modify,
an analyst needs a reliable, reproducible method to apply the modification directly to the target
web page in their browser.

This tool provides two practical deployment methods:
  1. USERSCRIPT GENERATOR (--template):
     Generates a ready-to-install Tampermonkey/Violentmonkey script (.user.js) with proven patterns:
     - `bypass-anti-debug`: Neutralizes `debugger;` loops, prevents console clearing, blocks DevTools traps.
     - `hook-api`: Intercepts `fetch()` and `XMLHttpRequest`, logging or modifying request/response payloads.
     - `dom-unlock`: Removes modal paywalls, enables disabled buttons, bypasses countdown timers, and re-enables right-click/copy.
     - `override-func`: Monkey-patches a specific global or object function with custom replacement logic.

  2. LOCAL MAP-LOCAL INTERCEPTOR PROXY (--serve):
     Starts a lightweight local HTTP proxy that intercepts web traffic and replaces specific remote
     JavaScript/HTML files with your modified local versions on the fly (Map Local).

USAGE
-----
  # 1. Generate anti-debugging bypass userscript for a target domain
  python web_modifier.py userscript --domain example.com --template bypass-anti-debug --out bypass.user.js

  # 2. Generate API hook userscript to inspect and modify fetch/XHR
  python web_modifier.py userscript --domain example.com --template hook-api --out api_hook.user.js

  # 3. Generate DOM unlocker userscript
  python web_modifier.py userscript --domain example.com --template dom-unlock --out unlock.user.js

  # 4. Generate custom function override
  python web_modifier.py userscript --domain example.com --template override-func \
      --func "window.checkPermission" --return-val "true" --out override.user.js

  # 5. Run local interceptor mock/proxy server to serve modified file
  python web_modifier.py serve --port 8080 --map-local "/static/app.js=./app.clean.js"

EXIT CODES
----------
  0 = successfully generated script or started server
  1 = error during generation or server startup
  2 = usage or argument error
"""

import argparse
import http.server
import json
import os
import sys
import urllib.parse
from pathlib import Path


# --------------------------------------------------------------------------- #
# Userscript Templates
# --------------------------------------------------------------------------- #

HEADER_TEMPLATE = """// ==UserScript==
// @name         {name}
// @namespace    apk-reverse.web-modifier
// @version      1.0
// @description  {desc}
// @match        *://{domain}/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {{
    'use strict';
    console.log('[WebModifier] Active on ' + window.location.hostname);

{body}
}})();
"""

TEMPLATE_ANTI_DEBUG = """    // --- 1. Neutralize debugger; loops and constructor tricks ---
    const _origFunction = window.Function;
    window.Function = function(...args) {
        if (args.length > 0 && typeof args[args.length - 1] === 'string') {
            const body = args[args.length - 1];
            if (body.includes('debugger') || body.includes('action')) {
                console.log('[WebModifier] Blocked dynamic anti-debug Function constructor');
                return function() {};
            }
        }
        return _origFunction.apply(this, args);
    };

    // --- 2. Neutralize setInterval / setTimeout debugger loops ---
    const _origSetInterval = window.setInterval;
    window.setInterval = function(fn, delay, ...args) {
        if (typeof fn === 'function') {
            const fnStr = fn.toString();
            if (fnStr.includes('debugger')) {
                console.log('[WebModifier] Blocked anti-debug setInterval loop');
                return -1;
            }
        }
        return _origSetInterval.call(window, fn, delay, ...args);
    };

    // --- 3. Prevent Console Clearing ---
    const _origClear = console.clear;
    console.clear = function() {
        console.log('[WebModifier] Prevented console.clear()');
    };

    // --- 4. Re-enable Right-Click and Copy ---
    ['contextmenu', 'copy', 'cut', 'selectstart'].forEach(event => {
        document.addEventListener(event, (e) => e.stopPropagation(), true);
    });
"""

TEMPLATE_HOOK_API = """    // --- 1. Intercept window.fetch ---
    const _origFetch = window.fetch;
    window.fetch = async function(resource, init = {}) {
        const url = (typeof resource === 'string') ? resource : resource.url;
        console.log('[Fetch Request] URL:', url);
        if (init && init.body) {
            console.log('[Fetch Payload]:', init.body);
        }

        // Call real fetch
        const response = await _origFetch.apply(this, arguments);

        // Clone response to read body without consuming it
        try {
            const clone = response.clone();
            clone.text().then(text => {
                console.log('[Fetch Response] ' + url + ' =>', text.slice(0, 500));
            });
        } catch(e) {}

        return response;
    };

    // --- 2. Intercept XMLHttpRequest ---
    const _origOpen = XMLHttpRequest.prototype.open;
    const _origSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._reqUrl = url;
        this._reqMethod = method;
        return _origOpen.apply(this, [method, url, ...rest]);
    };

    XMLHttpRequest.prototype.send = function(body) {
        console.log('[XHR Request] ' + this._reqMethod + ' ' + this._reqUrl, body);
        this.addEventListener('load', () => {
            console.log('[XHR Response] ' + this._reqUrl + ' =>', this.responseText.slice(0, 500));
        });
        return _origSend.apply(this, arguments);
    };
"""

TEMPLATE_DOM_UNLOCK = """    window.addEventListener('DOMContentLoaded', () => {
        // --- 1. Enable all disabled buttons and inputs ---
        document.querySelectorAll('button:disabled, input:disabled').forEach(el => {
            el.disabled = false;
            el.removeAttribute('disabled');
            el.classList.remove('disabled');
        });

        // --- 2. Remove common overlay / modal backdrop elements ---
        const blockedSelectors = [
            '.modal-backdrop', '.v-overlay', '.paywall', '#paywall',
            '.ad-container', '.popup-overlay', '.overlay'
        ];
        blockedSelectors.forEach(sel => {
            document.querySelectorAll(sel).forEach(el => el.remove());
        });

        // --- 3. Re-enable scrolling on body ---
        document.body.style.overflow = 'auto';
        document.documentElement.style.overflow = 'auto';

        // --- 4. Bypass Countdown Timers ---
        const origSetTimeout = window.setTimeout;
        window.setTimeout = function(fn, delay, ...args) {
            if (delay > 2000 && delay < 60000) {
                console.log('[WebModifier] Accelerated timer from ' + delay + 'ms to 0ms');
                delay = 0;
            }
            return origSetTimeout.call(window, fn, delay, ...args);
        };
    });
"""

TEMPLATE_OVERRIDE_FUNC = """    // --- Monkey Patch Target Function ---
    const targetPath = "{func_name}";
    const returnVal = {return_val};

    // Replace target function once available
    const applyOverride = () => {{
        try {{
            const parts = targetPath.split('.');
            let obj = window;
            for (let i = 0; i < parts.length - 1; i++) {{
                obj = obj[parts[i]];
                if (!obj) return false;
            }}
            const method = parts[parts.length - 1];
            if (typeof obj[method] === 'function' || obj[method] !== undefined) {{
                obj[method] = function(...args) {{
                    console.log('[WebModifier] Intercepted call to ' + targetPath + ' with args:', args);
                    return returnVal;
                }};
                console.log('[WebModifier] Successfully replaced ' + targetPath);
                return true;
            }}
        }} catch(e) {{}}
        return false;
    }};

    if (!applyOverride()) {{
        const timer = setInterval(() => {{
            if (applyOverride()) clearInterval(timer);
        }}, 100);
    }}
"""


def generate_userscript(domain: str, template: str, name: str | None = None,
                        func_name: str | None = None, return_val: str = "true",
                        custom_code: str | None = None) -> str:
    """Build a complete userscript string based on selected template."""
    clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    script_name = name or f"WebModifier - {clean_domain}"
    desc = f"Client-side modification for {clean_domain}"

    if template == 'bypass-anti-debug':
        body = TEMPLATE_ANTI_DEBUG
    elif template == 'hook-api':
        body = TEMPLATE_HOOK_API
    elif template == 'dom-unlock':
        body = TEMPLATE_DOM_UNLOCK
    elif template == 'override-func':
        if not func_name:
            func_name = "window.checkAllowed"
        body = TEMPLATE_OVERRIDE_FUNC.format(func_name=func_name, return_val=return_val)
    elif custom_code:
        body = "    " + custom_code.replace("\n", "\n    ")
    else:
        body = "    // Custom logic here\n"

    return HEADER_TEMPLATE.format(name=script_name, desc=desc, domain=clean_domain, body=body)


# --------------------------------------------------------------------------- #
# Local Mock & Interceptor Server
# --------------------------------------------------------------------------- #

class MapLocalHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP Handler supporting path-to-local-file mapping."""
    mappings: dict[str, str] = {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        req_path = parsed.path

        # Check if requested path matches any mapped rule
        for mapped_url, local_file in self.mappings.items():
            if req_path.endswith(mapped_url) or req_path == mapped_url:
                if os.path.isfile(local_file):
                    self.send_response(200)
                    if local_file.endswith('.js'):
                        self.send_header('Content-Type', 'application/javascript; charset=utf-8')
                    elif local_file.endswith('.html'):
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                    elif local_file.endswith('.json'):
                        self.send_header('Content-Type', 'application/json')
                    else:
                        self.send_header('Content-Type', 'text/plain')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    with open(local_file, 'rb') as fh:
                        self.wfile.write(fh.read())
                    print(f"  [INTERCEPTED & REPLACED] {req_path} => {local_file}")
                    return

        # Fallback to standard HTTP handler
        super().do_GET()


def run_local_server(port: int, mappings: list[str]):
    """Start local mock/interceptor server."""
    map_dict = {}
    for m in mappings:
        if '=' in m:
            url_part, file_part = m.split('=', 1)
            map_dict[url_part.strip()] = file_part.strip()

    MapLocalHandler.mappings = map_dict
    server_address = ('127.0.0.1', port)
    httpd = http.server.HTTPServer(server_address, MapLocalHandler)

    print(f"\n" + "=" * 60)
    print(f"  🚀 LOCAL INTERCEPTOR SERVER BERJALAN")
    print(f"=" * 60)
    print(f"  Host: http://127.0.0.1:{port}")
    print(f"  Rules ({len(map_dict)} mapping aktif):")
    for u, f in map_dict.items():
        print(f"    * {u}  =>  {f}")
    print("=" * 60)
    print("  Tekan Ctrl + C untuk menghentikan server.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server dihentikan.")
        httpd.server_close()


# --------------------------------------------------------------------------- #
# CLI Parser
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        prog='web_modifier',
        description='Generate Userscripts and run Map-Local interceptor server to modify live web apps',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # Subcommand: userscript
    p_usr = sub.add_parser('userscript', help='Generate Tampermonkey userscript (.user.js)')
    p_usr.add_argument('--domain', required=True, help='Target domain (e.g. example.com)')
    p_usr.add_argument('--template', choices=['bypass-anti-debug', 'hook-api', 'dom-unlock', 'override-func'],
                       default='bypass-anti-debug', help='Template to use')
    p_usr.add_argument('--name', help='Custom userscript name')
    p_usr.add_argument('--func', help='Target function path for override-func (e.g. window.checkVip)')
    p_usr.add_argument('--return-val', default='true', help='Return value for override-func (default: true)')
    p_usr.add_argument('--custom-code', help='Custom JavaScript code snippet to inject')
    p_usr.add_argument('--out', '-o', help='Path output file .user.js (if not specified, prints to stdout)')

    # Subcommand: serve
    p_srv = sub.add_parser('serve', help='Run local HTTP interceptor server')
    p_srv.add_argument('--port', type=int, default=8080, help='Port to bind (default: 8080)')
    p_srv.add_argument('--map-local', action='append', default=[],
                       help='Map URL path to local file (e.g. /app.js=./app.clean.js)')

    args = parser.parse_args()

    if args.command == 'userscript':
        script_content = generate_userscript(
            domain=args.domain,
            template=args.template,
            name=args.name,
            func_name=args.func,
            return_val=args.return_val,
            custom_code=args.custom_code
        )
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(script_content, encoding='utf-8')
            print(f"\n[OK] Userscript berhasil dibuat:")
            print(f"  File:     {args.out}")
            print(f"  Target:   {args.domain}")
            print(f"  Template: {args.template}")
            print(f"  Cara pasang: Buka Tampermonkey di Chrome/Edge -> Utilities -> Import from file -> Pilih file ini.\n")
        else:
            print(script_content)
        return 0

    elif args.command == 'serve':
        run_local_server(args.port, args.map_local)
        return 0

    return 2


if __name__ == '__main__':
    sys.exit(main())
