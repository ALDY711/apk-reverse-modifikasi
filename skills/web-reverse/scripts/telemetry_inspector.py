#!/usr/bin/env python3
"""Inspect JavaScript bundles or HAR files for browser fingerprinting vectors and anti-bot telemetry collection.

Detects Canvas, WebGL, AudioContext, Navigator, Screen, and Hardware API sniffing.
Can automatically generate a Tampermonkey/DevTools runtime monitoring or spoofing script.

Usage:
    python telemetry_inspector.py --input bundle.js
    python telemetry_inspector.py --input bundle.js --generate-hook --output monitor_hook.js --spoof
    python telemetry_inspector.py --help
"""

import argparse
import json
import re
import sys
from collections import defaultdict


FINGERPRINT_SIGNATURES = {
    "Canvas 2D": [
        (r'\.toDataURL\b', "Canvas rasterization export (toDataURL)"),
        (r'\.getImageData\b', "Pixel buffer reading (getImageData)"),
        (r'\.isPointInPath\b', "Vector path geometry probing"),
        (r'fillText\s*\(\s*["\'][^"\']{10,}', "Text rendering test string"),
    ],
    "WebGL / GPU": [
        (r'UNMASKED_VENDOR_WEBGL\b', "Hardware GPU Vendor sniffing"),
        (r'UNMASKED_RENDERER_WEBGL\b', "Hardware GPU Renderer sniffing"),
        (r'\.getParameter\b', "WebGL parameter extraction"),
        (r'\.getSupportedExtensions\b', "GPU extension list enumeration"),
        (r'\.getContextAttributes\b', "Graphics context capabilities"),
    ],
    "AudioContext": [
        (r'createOscillator\b', "Audio synthesis oscillator"),
        (r'createDynamicsCompressor\b', "DSP dynamics compressor processing"),
        (r'createAnalyser\b', "Audio frequency spectrum analyser"),
        (r'\.getChannelData\b', "Audio float buffer sampling"),
    ],
    "Navigator & Automation": [
        (r'navigator\.webdriver\b', "Headless/automation flag detection"),
        (r'navigator\.plugins\b', "Browser plugin enumeration"),
        (r'navigator\.languages?\b', "System locale and language profile"),
        (r'navigator\.hardwareConcurrency\b', "CPU core count sniffing"),
        (r'navigator\.deviceMemory\b', "RAM capacity probing"),
        (r'navigator\.userAgentData\b', "Client Hints platform extraction"),
        (r'cdc_[a-zA-Z0-9_]+', "Chromedriver internal artifact detection"),
        (r'window\.chrome\b', "Chromium runtime environment sniffing"),
        (r'__nightmare|callPhantom|_phantom\b', "Legacy headless framework detection"),
    ],
    "Screen & Window Geometry": [
        (r'screen\.colorDepth\b', "Display color depth"),
        (r'screen\.availWidth\b|screen\.availHeight\b', "Available screen dimension sniffing"),
        (r'\.getClientRects\b|\.getBoundingClientRect\b', "Sub-pixel font rendering / box sniffing"),
    ],
    "Sensor & Behavioral": [
        (r'["\']devicemotion["\']', "Accelerometer motion event tracking"),
        (r'["\']deviceorientation["\']', "Gyroscope orientation event tracking"),
        (r'["\']pointermove["\']|["\']mousemove["\']', "Mouse movement coordinate tracking"),
        (r'["\']touchmove["\']|["\']touchstart["\']', "Touch pressure and radius tracking"),
    ],
    "Anti-Debugging & Timing": [
        (r'Function\s*\(\s*["\']\s*debugger\s*["\']\s*\)', "Dynamic Function debugger loop"),
        (r'\bdebugger\s*;', "Static debugger statement"),
        (r'performance\.now\b', "High-resolution execution timing check"),
    ]
}


def scan_content(text: str) -> dict:
    """Scan JavaScript text for fingerprinting vectors."""
    findings = defaultdict(list)
    total_hits = 0

    for category, patterns in FINGERPRINT_SIGNATURES.items():
        for regex_str, desc in patterns:
            matches = list(re.finditer(regex_str, text))
            if matches:
                findings[category].append({
                    "description": desc,
                    "count": len(matches),
                    "pattern": regex_str
                })
                total_hits += len(matches)

    return {
        "total_hits": total_hits,
        "categories": dict(findings)
    }


def generate_hook_script(spoof: bool = False) -> str:
    """Generate a userscript/DevTools hook to monitor or spoof telemetry."""
    mode_text = "Monitor & Spoof" if spoof else "Monitor Only"
    lines = [
        "// ==UserScript==",
        f"// @name         Browser Telemetry & Fingerprint Interceptor ({mode_text})",
        "// @namespace    http://tampermonkey.net/",
        "// @version      1.0",
        "// @description  Intercept and log all fingerprinting and anti-bot sensor probes.",
        "// @run-at       document-start",
        "// @grant        none",
        "// ==/UserScript==",
        "",
        "(function() {",
        "  'use strict';",
        "  console.log('[*] Telemetry & Anti-Fingerprint Interceptor initialized.');",
        "",
        "  const hookedFns = new WeakSet();",
        "  const originalToString = Function.prototype.toString;",
        "  function markHooked(fn) {",
        "    hookedFns.add(fn);",
        "    return fn;",
        "  }",
        "  Function.prototype.toString = function() {",
        "    if (hookedFns.has(this)) return 'function () { [native code] }';",
        "    return originalToString.apply(this, arguments);",
        "  };",
        "  markHooked(Function.prototype.toString);",
        ""
    ]

    if spoof:
        lines.extend([
            "  // 1. Mask navigator.webdriver",
            "  Object.defineProperty(navigator, 'webdriver', {",
            "    get: () => undefined,",
            "    configurable: true",
            "  });",
            "",
            "  // 2. Spoof WebGL GPU Vendor & Renderer",
            "  const origGetParameter = WebGLRenderingContext.prototype.getParameter;",
            "  WebGLRenderingContext.prototype.getParameter = markHooked(function(param) {",
            "    if (param === 0x9245) { // UNMASKED_VENDOR_WEBGL",
            "      console.log('[SPOOF] WebGL Vendor requested -> Google Inc. (NVIDIA)');",
            "      return 'Google Inc. (NVIDIA)';",
            "    }",
            "    if (param === 0x9246) { // UNMASKED_RENDERER_WEBGL",
            "      console.log('[SPOOF] WebGL Renderer requested -> ANGLE (NVIDIA, GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)');",
            "      return 'ANGLE (NVIDIA, GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)';",
            "    }",
            "    return origGetParameter.apply(this, arguments);",
            "  });",
            ""
        ])

    lines.extend([
        "  // 3. Monitor Canvas toDataURL / getImageData",
        "  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;",
        "  HTMLCanvasElement.prototype.toDataURL = markHooked(function(...args) {",
        "    console.warn('[TELEMETRY] Canvas.toDataURL() invoked:', args);",
        "    return origToDataURL.apply(this, args);",
        "  });",
        "",
        "  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;",
        "  CanvasRenderingContext2D.prototype.getImageData = markHooked(function(...args) {",
        "    console.warn('[TELEMETRY] Canvas.getImageData() invoked:', args);",
        "    return origGetImageData.apply(this, args);",
        "  });",
        "",
        "  // 4. Monitor AudioContext Creation",
        "  if (window.AudioContext) {",
        "    const origOscillator = AudioContext.prototype.createOscillator;",
        "    AudioContext.prototype.createOscillator = markHooked(function(...args) {",
        "      console.warn('[TELEMETRY] AudioContext createOscillator() invoked');",
        "      return origOscillator.apply(this, args);",
        "    });",
        "  }",
        "",
        "  // 5. Monitor Navigator Properties",
        "  const watchedNavProps = ['languages', 'hardwareConcurrency', 'deviceMemory', 'plugins'];",
        "  for (const prop of watchedNavProps) {",
        "    const origVal = navigator[prop];",
        "    try {",
        "      Object.defineProperty(navigator, prop, {",
        "        get: function() {",
        "          console.log(`[TELEMETRY] navigator.${prop} accessed ->`, origVal);",
        "          return origVal;",
        "        },",
        "        configurable: true",
        "      });",
        "    } catch(e) {}",
        "  }",
        "",
        "})();"
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Inspect JavaScript bundles or HAR files for browser fingerprinting and anti-bot telemetry."
    )
    parser.add_argument("--input", "-i", type=str, help="Path to JavaScript file or HAR file to analyze")
    parser.add_argument("--generate-hook", action="store_true", help="Generate Tampermonkey/DevTools hook script")
    parser.add_argument("--spoof", action="store_true", help="Include spoofing values in generated hook (default: monitor only)")
    parser.add_argument("--output", "-o", type=str, help="Output file path for analysis report or generated hook script")

    args = parser.parse_args()

    if args.generate_hook:
        hook_code = generate_hook_script(spoof=args.spoof)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(hook_code)
            print(f"[+] Hook script saved to: {args.output}")
        else:
            print(hook_code)
        return

    if not args.input:
        parser.print_help()
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        sys.exit(f"[-] Failed to read input file: {e}")

    results = scan_content(content)

    if args.output and args.output.endswith(".json"):
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Scan results saved to {args.output}")
        return

    print("=" * 70)
    print(" BROWSER FINGERPRINTING & TELEMETRY AUDIT REPORT")
    print(f" Target File: {args.input}")
    print(f" Total Detection Hits: {results['total_hits']}")
    print("=" * 70)

    if not results["categories"]:
        print("[✓] No common browser fingerprinting vectors detected.")
        return

    for category, items in results["categories"].items():
        print(f"\n[!] Category: {category}")
        for item in items:
            print(f"    - {item['description']}: {item['count']} hit(s)")

    print("\n" + "=" * 70)
    print("Tip: Run with `--generate-hook --output hook.js` to create a live runtime tracer.")


if __name__ == "__main__":
    main()
