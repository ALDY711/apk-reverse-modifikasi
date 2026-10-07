#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate dynamic DevTools Console snippets and Tampermonkey/Violentmonkey Userscripts.

WHY THIS EXISTS
---------------
During web reverse engineering, static analysis of minified or obfuscated JavaScript only
gets you halfway. To understand dynamic runtime state—such as the exact moment a request
is signed, what AES encryption key is generated, or why the tab freezes due to an infinite
`debugger;` loop—analysts need dynamic runtime instrumentation (hooking).

In mobile apps we use Frida. In the browser, we use Prototype Hooking, Proxy Traps, and
DOM/BOM Overrides injected at `document-start`.

This tool generates production-ready, bulletproof injection scripts for:
  1. Universal Anti-Anti-Debugging (defeats infinite debugger loops, timing checks, console traps)
  2. Universal Fetch & XMLHttpRequest Snooper with Caller Stack Trace
  3. WebCrypto & CryptoJS Runtime Sniffer (logs AES/RSA/HMAC keys, IVs, plaintexts, and hashes)
  4. LocalStorage, SessionStorage & Cookie Access Monitor
  5. WebSocket Frame Inspector
  6. All-In-One Unified Reverse Engineering Harness

USAGE
-----
  # Generate All-In-One Tampermonkey userscript for target domain
  python devtools_hook_generator.py --type userscript --mode all --domain example.com --out reverse_harness.user.js

  # Generate DevTools Console snippet to defeat anti-debug
  python devtools_hook_generator.py --type snippet --mode anti-debug --out defeat_debugger.js

  # Generate Crypto Sniffer to extract AES/HMAC keys and hashes in real-time
  python devtools_hook_generator.py --type userscript --mode crypto --domain api.target.com --out crypto_sniff.user.js

  # Generate Fetch & XHR hook with caller stack traces
  python devtools_hook_generator.py --type snippet --mode fetch-xhr

EXIT CODES
----------
  0 = script generated successfully
  2 = argument or parameter error
"""

import argparse
import sys
from pathlib import Path


SNIPPET_ANTI_DEBUG = r"""
// =========================================================================
// [WEB-REVERSE] Universal Anti-Anti-Debugging & DevTools Neutralizer
// =========================================================================
(function() {
  'use strict';
  console.log('%c[Anti-Debug]%c Initializing neutralizer...', 'color: #00ffaa; font-weight: bold;', 'color: auto;');

  // 1. Defeat Function constructor anti-debug: Function("debugger")()
  const OriginalFunction = window.Function;
  const FunctionHandler = {
    construct(target, args) {
      if (args.length > 0) {
        const body = args[args.length - 1];
        if (typeof body === 'string' && body.includes('debugger')) {
          console.warn('[Anti-Debug] Blocked new Function containing debugger;');
          args[args.length - 1] = body.replace(/\bdebugger\b/g, '/* blocked debugger */');
        }
      }
      return new target(...args);
    },
    apply(target, thisArg, args) {
      if (args.length > 0) {
        const body = args[args.length - 1];
        if (typeof body === 'string' && body.includes('debugger')) {
          console.warn('[Anti-Debug] Blocked Function call containing debugger;');
          args[args.length - 1] = body.replace(/\bdebugger\b/g, '/* blocked debugger */');
        }
      }
      return target.apply(thisArg, args);
    }
  };
  window.Function = new Proxy(OriginalFunction, FunctionHandler);
  window.Function.prototype = OriginalFunction.prototype;

  // 2. Defeat eval("debugger")
  const origEval = window.eval;
  window.eval = function(code) {
    if (typeof code === 'string' && code.includes('debugger')) {
      console.warn('[Anti-Debug] Blocked eval() containing debugger;');
      code = code.replace(/\bdebugger\b/g, '/* blocked debugger */');
    }
    return origEval.call(this, code);
  };

  // 3. Prevent aggressive console.clear() used to wipe logs
  const origConsoleClear = console.clear;
  console.clear = function() {
    console.warn('[Anti-Debug] Suppressed console.clear()');
  };

  // 4. Neutralize timing-based DevTools detection
  const origDateNow = Date.now;
  let lastTime = origDateNow.call(Date);
  Date.now = function() {
    const current = origDateNow.call(Date);
    // If delta exceeds 1000ms suddenly (paused in breakpoint), clamp delta
    if (current - lastTime > 2000) {
      lastTime += 100;
      return lastTime;
    }
    lastTime = current;
    return current;
  };

  // 5. Spoof window dimension deltas (outerWidth - innerWidth > 160 detection)
  try {
    Object.defineProperty(window, 'outerWidth', {
      get: () => window.innerWidth,
      configurable: true
    });
    Object.defineProperty(window, 'outerHeight', {
      get: () => window.innerHeight,
      configurable: true
    });
  } catch (e) {}

  console.log('%c[Anti-Debug]%c Active & Monitoring.', 'color: #00ffaa; font-weight: bold;', 'color: auto;');
})();
"""

SNIPPET_FETCH_XHR = r"""
// =========================================================================
// [WEB-REVERSE] Universal Fetch & XMLHttpRequest Snooper
// =========================================================================
(function() {
  'use strict';
  console.log('%c[API-Snooper]%c Hooking window.fetch and XMLHttpRequest...', 'color: #ff9900; font-weight: bold;', 'color: auto;');

  function cleanStack(stack) {
    if (!stack) return '';
    return stack.split('\n').slice(2, 6).map(l => l.trim()).join('\n    ');
  }

  // 1. Hook window.fetch
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const callStack = new Error().stack;
    const url = (typeof args[0] === 'string') ? args[0] : (args[0]?.url || 'UNKNOWN_URL');
    const opts = args[1] || {};
    const method = opts.method || 'GET';

    console.groupCollapsed(`%c[FETCH] ${method}%c ${url}`, 'color: #00e5ff; font-weight: bold;', 'color: #fff;');
    console.log('Headers:', opts.headers || {});
    if (opts.body) {
      try {
        console.log('Body (JSON):', JSON.parse(opts.body));
      } catch (e) {
        console.log('Body (Raw):', opts.body);
      }
    }
    console.log('Called from:\n   ', cleanStack(callStack));
    console.groupEnd();

    try {
      const response = await origFetch.apply(this, args);
      const clone = response.clone();
      clone.text().then(text => {
        let parsed = text;
        try { parsed = JSON.parse(text); } catch (e) {}
        console.groupCollapsed(`%c[FETCH RESP] ${response.status}%c ${url}`, 'color: #76ff03; font-weight: bold;', 'color: #aaa;');
        console.log('Response Body:', parsed);
        console.groupEnd();
      }).catch(() => {});
      return response;
    } catch (err) {
      console.error(`[FETCH FAIL] ${method} ${url}:`, err);
      throw err;
    }
  };

  // 2. Hook XMLHttpRequest
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const origSetReqHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._reqMethod = method;
    this._reqUrl = url;
    this._reqHeaders = {};
    this._callStack = new Error().stack;
    return origOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
    if (this._reqHeaders) {
      this._reqHeaders[header] = value;
    }
    return origSetReqHeader.call(this, header, value);
  };

  XMLHttpRequest.prototype.send = function(body) {
    console.groupCollapsed(`%c[XHR] ${this._reqMethod}%c ${this._reqUrl}`, 'color: #ff4081; font-weight: bold;', 'color: #fff;');
    console.log('Headers:', this._reqHeaders || {});
    if (body) {
      try {
        console.log('Body (JSON):', JSON.parse(body));
      } catch (e) {
        console.log('Body (Raw):', body);
      }
    }
    console.log('Called from:\n   ', cleanStack(this._callStack));
    console.groupEnd();

    this.addEventListener('load', function() {
      console.groupCollapsed(`%c[XHR RESP] ${this.status}%c ${this._reqUrl}`, 'color: #b2ff59; font-weight: bold;', 'color: #aaa;');
      try {
        console.log('Response:', JSON.parse(this.responseText));
      } catch (e) {
        console.log('Response (Raw):', this.responseText);
      }
      console.groupEnd();
    });

    return origSend.call(this, body);
  };

  console.log('%c[API-Snooper]%c Active & Capturing traffic.', 'color: #ff9900; font-weight: bold;', 'color: auto;');
})();
"""

SNIPPET_CRYPTO = r"""
// =========================================================================
// [WEB-REVERSE] WebCrypto & CryptoJS Runtime Sniffer
// =========================================================================
(function() {
  'use strict';
  console.log('%c[Crypto-Sniffer]%c Hooking WebCrypto and CryptoJS...', 'color: #e040fb; font-weight: bold;', 'color: auto;');

  function ab2hex(buffer) {
    return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function ab2str(buffer) {
    try {
      return new TextDecoder().decode(buffer);
    } catch (e) {
      return ab2hex(buffer);
    }
  }

  // 1. Hook window.crypto.subtle
  if (window.crypto && window.crypto.subtle) {
    const origEncrypt = window.crypto.subtle.encrypt;
    window.crypto.subtle.encrypt = async function(algorithm, key, data) {
      console.group('%c[WebCrypto] subtle.encrypt()%c', 'color: #00e676; font-weight: bold;', 'color: auto;');
      console.log('Algorithm:', algorithm);
      console.log('Key Object:', key);
      console.log('Plaintext (String):', ab2str(data));
      console.log('Plaintext (Hex):', ab2hex(data));
      console.log('Stack:\n', new Error().stack);
      console.groupEnd();

      const ciphertext = await origEncrypt.call(this, algorithm, key, data);
      console.log('%c[WebCrypto] Ciphertext Result (Hex):%c', 'color: #00e676; font-weight: bold;', 'color: auto;', ab2hex(ciphertext));
      return ciphertext;
    };

    const origDecrypt = window.crypto.subtle.decrypt;
    window.crypto.subtle.decrypt = async function(algorithm, key, data) {
      console.group('%c[WebCrypto] subtle.decrypt()%c', 'color: #00e676; font-weight: bold;', 'color: auto;');
      console.log('Algorithm:', algorithm);
      console.log('Key Object:', key);
      console.log('Ciphertext IN (Hex):', ab2hex(data));
      console.log('Stack:\n', new Error().stack);
      console.groupEnd();

      const plaintext = await origDecrypt.call(this, algorithm, key, data);
      console.groupCollapsed('%c[WebCrypto] Plaintext Decrypted Result%c', 'color: #00e676; font-weight: bold;', 'color: auto;');
      console.log('Plaintext (String):', ab2str(plaintext));
      console.log('Plaintext (Hex):', ab2hex(plaintext));
      console.groupEnd();
      return plaintext;
    };

    const origDigest = window.crypto.subtle.digest;
    window.crypto.subtle.digest = async function(algorithm, data) {
      const result = await origDigest.call(this, algorithm, data);
      console.groupCollapsed(`%c[WebCrypto] digest(${typeof algorithm === 'string' ? algorithm : algorithm.name})%c`, 'color: #ffab00; font-weight: bold;', 'color: auto;');
      console.log('Input (String):', ab2str(data));
      console.log('Input (Hex):', ab2hex(data));
      console.log('Digest (Hex):', ab2hex(result));
      console.groupEnd();
      return result;
    };
  }

  // 2. Poll & Hook CryptoJS when it becomes available on window
  function hookCryptoJS() {
    if (!window.CryptoJS || window.CryptoJS._hooked) return;
    window.CryptoJS._hooked = true;
    console.log('%c[Crypto-Sniffer]%c CryptoJS detected! Attaching hooks...', 'color: #e040fb; font-weight: bold;', 'color: auto;');

    // Hook AES
    if (window.CryptoJS.AES && window.CryptoJS.AES.encrypt) {
      const origAesEncrypt = window.CryptoJS.AES.encrypt;
      window.CryptoJS.AES.encrypt = function(message, key, cfg) {
        console.group('%c[CryptoJS.AES.encrypt]%c', 'color: #e040fb; font-weight: bold;', 'color: auto;');
        console.log('Message:', typeof message === 'object' ? message.toString() : message);
        console.log('Key:', typeof key === 'object' ? key.toString() : key);
        console.log('Config (IV/Mode):', cfg);
        console.log('Stack:\n', new Error().stack);
        console.groupEnd();
        return origAesEncrypt.apply(this, arguments);
      };
    }

    if (window.CryptoJS.AES && window.CryptoJS.AES.decrypt) {
      const origAesDecrypt = window.CryptoJS.AES.decrypt;
      window.CryptoJS.AES.decrypt = function(ciphertext, key, cfg) {
        console.group('%c[CryptoJS.AES.decrypt]%c', 'color: #e040fb; font-weight: bold;', 'color: auto;');
        console.log('Ciphertext:', typeof ciphertext === 'object' ? ciphertext.toString() : ciphertext);
        console.log('Key:', typeof key === 'object' ? key.toString() : key);
        console.log('Config (IV/Mode):', cfg);
        console.log('Stack:\n', new Error().stack);
        console.groupEnd();

        const res = origAesDecrypt.apply(this, arguments);
        try {
          console.log('%c[CryptoJS.AES.decrypt Result]%c', 'color: #00e676; font-weight: bold;', 'color: auto;', res.toString(window.CryptoJS.enc.Utf8));
        } catch(e) {
          console.log('%c[CryptoJS.AES.decrypt Result (Hex)]%c', 'color: #00e676; font-weight: bold;', 'color: auto;', res.toString());
        }
        return res;
      };
    }

    // Hook HmacSHA256
    if (window.CryptoJS.HmacSHA256) {
      const origHmac = window.CryptoJS.HmacSHA256;
      window.CryptoJS.HmacSHA256 = function(message, key) {
        const res = origHmac.apply(this, arguments);
        console.groupCollapsed('%c[CryptoJS.HmacSHA256]%c', 'color: #ff4081; font-weight: bold;', 'color: auto;');
        console.log('Message:', typeof message === 'object' ? message.toString() : message);
        console.log('Secret Key:', typeof key === 'object' ? key.toString() : key);
        console.log('Result Hash:', res.toString());
        console.groupEnd();
        return res;
      };
    }

    // Hook MD5
    if (window.CryptoJS.MD5) {
      const origMd5 = window.CryptoJS.MD5;
      window.CryptoJS.MD5 = function(message) {
        const res = origMd5.apply(this, arguments);
        console.groupCollapsed('%c[CryptoJS.MD5]%c', 'color: #ff9100; font-weight: bold;', 'color: auto;');
        console.log('Input:', typeof message === 'object' ? message.toString() : message);
        console.log('MD5 Hash:', res.toString());
        console.groupEnd();
        return res;
      };
    }
  }

  setInterval(hookCryptoJS, 500);
})();
"""

SNIPPET_STORAGE = r"""
// =========================================================================
// [WEB-REVERSE] Storage & Cookie Access Observer
// =========================================================================
(function() {
  'use strict';
  console.log('%c[Storage-Observer]%c Tracking LocalStorage, SessionStorage, and Cookies...', 'color: #00b0ff; font-weight: bold;', 'color: auto;');

  // 1. Hook localStorage.setItem
  const origLocalSet = Storage.prototype.setItem;
  Storage.prototype.setItem = function(key, value) {
    const isLocal = this === window.localStorage;
    const storeName = isLocal ? 'localStorage' : 'sessionStorage';
    console.groupCollapsed(`%c[${storeName}.setItem]%c ${key}`, 'color: #00b0ff; font-weight: bold;', 'color: #fff;');
    try {
      console.log('Parsed Value:', JSON.parse(value));
    } catch (e) {
      console.log('Raw Value:', value);
    }
    console.log('Stack:\n', new Error().stack);
    console.groupEnd();
    return origLocalSet.call(this, key, value);
  };

  // 2. Hook document.cookie setter
  try {
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                       Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
    if (cookieDesc && cookieDesc.set) {
      const origCookieSet = cookieDesc.set;
      Object.defineProperty(document, 'cookie', {
        set: function(val) {
          console.groupCollapsed(`%c[document.cookie]%c ${val.split(';')[0]}`, 'color: #ffd600; font-weight: bold;', 'color: #fff;');
          console.log('Full Cookie String:', val);
          console.log('Stack:\n', new Error().stack);
          console.groupEnd();
          return origCookieSet.call(this, val);
        },
        get: cookieDesc.get,
        configurable: true
      });
    }
  } catch (e) {}
})();
"""

SNIPPET_WEBSOCKET = r"""
// =========================================================================
// [WEB-REVERSE] WebSocket Frame Snooper & Frame Inspector
// =========================================================================
(function() {
  'use strict';
  console.log('%c[WS-Snooper]%c Hooking WebSocket prototype...', 'color: #7c4dff; font-weight: bold;', 'color: auto;');

  const OrigWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const ws = protocols ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    console.log(`%c[WS OPEN]%c Connecting to ${url}`, 'color: #7c4dff; font-weight: bold;', 'color: #fff;');

    const origSend = ws.send;
    ws.send = function(data) {
      console.groupCollapsed(`%c[WS SEND]%c ${url}`, 'color: #ff5252; font-weight: bold;', 'color: #aaa;');
      if (typeof data === 'string') {
        try { console.log('JSON Payload:', JSON.parse(data)); } catch (e) { console.log('Raw Text:', data); }
      } else {
        console.log('Binary Payload:', data);
      }
      console.log('Stack:\n', new Error().stack);
      console.groupEnd();
      return origSend.call(this, data);
    };

    ws.addEventListener('message', function(event) {
      console.groupCollapsed(`%c[WS RECV]%c ${url}`, 'color: #69f0ae; font-weight: bold;', 'color: #aaa;');
      if (typeof event.data === 'string') {
        try { console.log('JSON Payload:', JSON.parse(event.data)); } catch (e) { console.log('Raw Text:', event.data); }
      } else {
        console.log('Binary Frame:', event.data);
      }
      console.groupEnd();
    });

    return ws;
  };
  window.WebSocket.prototype = OrigWebSocket.prototype;
})();
"""


def build_userscript_header(domain: str, name: str = "Web Reverse Engineering Harness") -> str:
    match_rule = f"*://*.{domain}/*" if domain != "*" else "*://*/*"
    return f"""// ==UserScript==
// @name         {name}
// @namespace    https://antigravity.dev/web-reverse
// @version      2.0
// @description  Dynamic runtime instrumentation for web reverse engineering, anti-debug bypass, and API tracing.
// @author       Antigravity Web-Reverse Tool
// @match        {match_rule}
// @run-at       document-start
// @grant        unsafeWindow
// ==/UserScript==

// Ensure we attach to the real page context
const window = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
"""


def main():
    parser = argparse.ArgumentParser(
        description="DevTools Console Snippet & Userscript Generator for Web Reverse Engineering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type", "-t",
        choices=["snippet", "userscript"],
        default="userscript",
        help="Output type: 'snippet' (DevTools console) or 'userscript' (Tampermonkey @run-at document-start)",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["all", "anti-debug", "fetch-xhr", "crypto", "storage", "websocket"],
        default="all",
        help="Hooking focus: anti-debug, fetch-xhr, crypto, storage, websocket, or all",
    )
    parser.add_argument(
        "--domain", "-d",
        default="*",
        help="Target domain matching rule for Userscript (e.g. 'example.com' or '*')",
    )
    parser.add_argument(
        "--out", "-o",
        help="Output file path. If omitted, prints script to stdout.",
    )

    args = parser.parse_args()

    # Collect snippets based on mode
    selected_snippets = []
    if args.mode == "all":
        selected_snippets = [SNIPPET_ANTI_DEBUG, SNIPPET_FETCH_XHR, SNIPPET_CRYPTO, SNIPPET_STORAGE, SNIPPET_WEBSOCKET]
    elif args.mode == "anti-debug":
        selected_snippets = [SNIPPET_ANTI_DEBUG]
    elif args.mode == "fetch-xhr":
        selected_snippets = [SNIPPET_FETCH_XHR]
    elif args.mode == "crypto":
        selected_snippets = [SNIPPET_CRYPTO]
    elif args.mode == "storage":
        selected_snippets = [SNIPPET_STORAGE]
    elif args.mode == "websocket":
        selected_snippets = [SNIPPET_WEBSOCKET]

    body = "\n".join(selected_snippets).strip()

    if args.type == "userscript":
        script_name = f"Web Reverse [{args.mode.upper()}] - {args.domain}"
        header = build_userscript_header(args.domain, script_name)
        full_script = f"{header}\n{body}\n"
    else:
        full_script = f"// [DEVTOOLS SNIPPET: {args.mode.upper()}]\n// Paste this into DevTools Console.\n\n{body}\n"

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(full_script, encoding='utf-8')
        print(f"[+] Successfully generated {args.type} ({args.mode}) -> {out_path.resolve()}")
    else:
        print(full_script)

    sys.exit(0)


if __name__ == "__main__":
    main()
