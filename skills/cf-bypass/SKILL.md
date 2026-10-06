---
name: cf-bypass
description: "Bypass and solve Cloudflare IUAM (I'm Under Attack Mode), Turnstile challenges, Bot Fight Mode, and Enterprise WAF for web scraping and API reverse engineering. Features multi-tiered escalation (Direct-to-Origin bypass, CF Worker Proxy, got-scraping, curl_cffi JA3/JA4, humanoid-js, Puppeteer Stealth, PRB, Cantarella Rebrowser+Ghost Cursor, and Camoufox C++ engine spoofing)."
license: MIT
compatibility: "Node.js 20+, Python 3.9+. Optional: Bun, Xvfb (Linux), Chrome/Chromium/Camoufox binary."
metadata:
  version: "4.0"
  reference_project: "C:\\streming-anime\\backend"
  reference_files:
    - "C:\\streming-anime\\backend\\src\\helpers\\getHTML.ts"
    - "C:\\streming-anime\\backend\\.cf-bypass\\src\\index.ts"
    - "C:\\streming-anime\\backend\\.cf-bypass\\src\\lib\\browser\\br.ts"
    - "C:\\streming-anime\\backend\\.cf-bypass\\src\\lib\\ends\\iuam.ts"
    - "C:\\streming-anime\\backend\\.cf-bypass\\src\\lib\\ends\\turnstile.ts"
    - "C:\\streming-anime\\backend\\src\\controllers\\proxy.controller.ts"
    - "C:\\streming-anime\\backend\\package.json"
    - "C:\\streming-anime\\backend\\.cf-bypass\\package.json"
  last_reconstruction_pass: "2026-10-06"
---

# Cloudflare (CF) Challenge Solver & Bypass Architecture — Master Reference Manual

This skill is the definitive technical manual for analyzing, bypassing, and solving Cloudflare edge security—ranging from passive Bot Management, IUAM ("Just a moment..."), and Turnstile interactive CAPTCHA widgets to Enterprise WAF rules (Error 1020 / HTTP 403).

This guide incorporates battle-tested production architectures from `C:\streming-anime\backend` and extends significantly beyond it with advanced techniques: **Direct-to-Origin DNS resolution**, **TCP/IP stack OS tuning (p0f bypass)**, **Camoufox C++ engine-level spoofing**, **Web Worker PoW challenge introspection**, **`__cf_bm` behavioral cookie analysis**, and **External CAPTCHA solver bridges**.

---

## TABLE OF CONTENTS

1. [The 6 Layers of Cloudflare Defense](#1-the-6-layers-of-cloudflare-defense)
2. [Critical Operational Rules (R1 - R14)](#2-critical-operational-rules-r1---r14)
3. [The Direct-to-Origin Bypass (Zero-Challenge Solution)](#3-the-direct-to-origin-bypass-zero-challenge-solution)
4. [Multi-Tier Escalation Architecture (Tiers 0 to 7)](#4-multi-tier-escalation-architecture-tiers-0-to-7)
   - [Tier -1: Direct-to-Origin Bypass (`cf_origin_finder.py`)](#tier--1-direct-to-origin-bypass-cf_origin_finderpy)
   - [Tier 0: Cloudflare Worker Edge Reverse Proxy (`cf_worker_proxy.js`)](#tier-0-cloudflare-worker-edge-reverse-proxy-cf_worker_proxyjs)
   - [Tier 1: TLS Fingerprint Emulation (`got-scraping`)](#tier-1-tls-fingerprint-emulation-got-scraping)
   - [Tier 2: Native JA3/JA4 Impersonation (`curl_cffi` / `tls-client`)](#tier-2-native-ja3ja4-impersonation-curl_cffi--tls-client)
   - [Tier 3: Sandboxed V8 Math Evaluator (`humanoid-js`)](#tier-3-sandboxed-v8-math-evaluator-humanoid-js)
   - [Tier 4: Optimized Puppeteer Stealth with Resource Aborting](#tier-4-optimized-puppeteer-stealth-with-aggressive-resource-aborting)
   - [Tier 5: Puppeteer Real Browser (PRB) with Singleton Pooling & XVFB](#tier-5-puppeteer-real-browser-prb-with-singleton-pooling--xvfb)
   - [Tier 6: Cantarella Bypass Sidecar (Rebrowser + Ghost Cursor + CDP Patch)](#tier-6-cantarella-bypass-sidecar-rebrowser--ghost-cursor--cdp-patch)
   - [Tier 7: External CAPTCHA Solver Bridge (`turnstile_api_solver.py`)](#tier-7-external-captcha-solver-bridge-turnstile_api_solverpy)
5. [Advanced Network & OS Fingerprinting (TCP SYN / p0f Tuning)](#5-advanced-network--os-fingerprinting-tcp-syn--p0f-tuning)
6. [Engine-Level Anti-Bot Neutralization (Camoufox vs Rebrowser)](#6-engine-level-anti-bot-neutralization-camoufox-vs-rebrowser)
7. [Cloudflare Cookie Anatomy & Behavioral Tracking (`__cf_bm`, `cf_clearance`)](#7-cloudflare-cookie-anatomy--behavioral-tracking-__cf_bm-cf_clearance)
8. [Turnstile Execution Modes, Kinematics Mathematics, & Coordinate Solving](#8-turnstile-execution-modes-kinematics-mathematics--coordinate-solving)
9. [Web Worker PoW Challenge Execution & Introspection](#9-web-worker-pow-challenge-execution--introspection)
10. [Hardware, Sensor, & Font Fingerprint Vectors](#10-hardware-sensor--font-fingerprint-vectors)
11. [Cookie Jar Management, Caching, & Token Replay](#11-cookie-jar-management-caching--token-replay)
12. [Subprocess & Memory Management (Preventing Zombie Chromium)](#12-subprocess--memory-management-preventing-zombie-chromium)
13. [Proxy Strategies & IP Reputation Engineering](#13-proxy-strategies--ip-reputation-engineering)
14. [CLI Toolset Reference & Workflows](#14-cli-toolset-reference--workflows)
15. [Encyclopedic Troubleshooting Matrix & Diagnostic Flowchart](#15-encyclopedic-troubleshooting-matrix--diagnostic-flowchart)

---

## 1. THE 6 LAYERS OF CLOUDFLARE DEFENSE

```
[Incoming Request]
       │
       ▼
[LAYER 1: IP Reputation & ASN Intelligence] ──► Block datacenter IPs / Tor / flagged VPNs
       │
       ▼
[LAYER 2: TCP Stack & TLS Client Hello (JA3/JA4)] ──► Mismatch between OS TCP SYN & TLS ciphers
       │
       ▼
[LAYER 3: HTTP/2 Header Ordering & Frame Signatures] ──► Flags non-browser pseudo-header sequences
       │
       ▼
[LAYER 4: Passive JS Challenge (IUAM - "Just a moment...")] ──► Sandboxed DOM/Canvas/WebAudio benchmark
       │
       ▼
[LAYER 5: Interactive Turnstile CAPTCHA & Behavioral Heuristics] ──► Evaluates mouse Bezier trajectories & CDP leaks
       │
       ▼
[LAYER 6: Custom WAF Rules & Enterprise Rate Limiting] ──► Error 1020 / Error 1015 / Geo-blocking
       │
       ▼
[Origin Web Server / API Response]
```

---

## 2. CRITICAL OPERATIONAL RULES (R1 - R14)

Violating any of these rules will result in immediate HTTP 403 Forbidden responses, infinite challenge loops, or severe server memory exhaustion.

### R1 — Cryptographic Fingerprint & User-Agent Synchronization
The `cf_clearance` cookie issued upon solving a challenge is cryptographically bound to three immutable facets:
1. **The exact `User-Agent` string** present during challenge generation (byte-for-byte identical).
2. **The client's TLS Client Hello fingerprint (JA3 / JA4)**, including cipher suite ordering, extensions, elliptic curves, and ALPN negotiation.
3. **The egress IP address** (in strict WAF mode).

* **Anti-pattern:** Solving a challenge in Chrome 133, extracting `cf_clearance`, and replaying the request using Python `requests`. Python's OpenSSL cipher ordering immediately triggers Cloudflare's JA3 mismatch filter, discarding the cookie.
* **Prescribed Action:** Replay requests exclusively via `got-scraping` (Node.js) or `curl_cffi` / `tls-client` (Python), configured to mimic the exact browser version that solved the challenge.

### R2 — Non-Destructive Early Detection Threshold
Always verify if an endpoint is actually blocked before spawning browser automation. Spawning Chromium costs 150MB–400MB RAM and 2–5 seconds of CPU time.
* **Standard:** If HTML size > 30KB and title does not contain "just a moment" or "attention required", the page is clean HTML.

### R3 — Strict Ascending Escalation Hierarchy
Never jump directly to heavy browser automation. Always execute tiers in order:
`Direct Origin (-1)` -> `CF Worker (0)` -> `got-scraping (1)` -> `curl_cffi (2)` -> `humanoid-js (3)` -> `Puppeteer Stealth (4)` -> `PRB (5)` -> `Cantarella (6)` -> `Solver API (7)`.

### R4 — Multi-Layer Token Caching & Proactive TTL Management
Cache the tuple `(domain, cf_clearance, user_agent, headers)` with a 25-minute TTL. Invalidate cache only when a request returns HTTP 403 or contains challenge indicators.

### R5 — Aggressive Resource Interception in Headless Browsers
When browser automation is necessary, abort all media, image, stylesheet, and font requests:
```typescript
await page.setRequestInterception(true);
page.on('request', (req) => {
  if (['image', 'stylesheet', 'font', 'media'].includes(req.resourceType())) req.abort();
  else req.continue();
});
```
* **Impact:** Reduces page load time by ~75% and cuts Chromium memory footprint from ~400MB down to ~120MB per tab.

### R6 — Neutralize CDP `Runtime.enable` Detection Leak
Standard `puppeteer` leaks `window.cdc_adoQpoasnfa76pfcZLmcfl_Array` and CDP console listeners. Use `rebrowser-puppeteer-core` with isolated execution contexts (`utilityWorld`), which prevents Cloudflare from detecting CDP hooks.

### R7 — Natural Mouse Motion via Bezier Curves (Ghost Cursor)
Never execute direct synthetic `page.click(selector)` on Turnstile checkboxes. Use `ghost-cursor` to generate human-like Fitts's Law / cubic Bezier trajectory paths with organic micro-overshoots and variable click delays (50ms–150ms).

### R8 — Rigorous Process & Subprocess Cleanup (`tree-kill`)
Track Chromium PIDs and wrap termination handlers with `tree-kill(pid, 'SIGKILL')` to ensure all child helper processes and XVFB wrappers are cleanly purged from memory.

### R9 — Proxy Header Cleansing
Strip internal Cloudflare headers (`cf-connecting-ip`, `cf-ray`, `cf-visitor`, `x-forwarded-for`) before re-transmitting through reverse proxies.

### R10 — Viewport & Screen Dimension Consistency
Ensure `window.innerWidth`, `window.outerWidth`, `screen.width`, and `window.devicePixelRatio` form a mathematically consistent desktop display (e.g. 1920x1080 with 1.0 ratio).

### R11 — Prevent Canvas & WebGL Entropy Anomalies
Do not inject random noise into Canvas or WebGL data unless specifically required. Naive noise breaks Cloudflare's internal rendering hash verification, causing automatic challenge failure.

### R12 — Cloudflare Worker Egress Routing for ASN Trust
For targets with aggressive IP blocking against VPS providers, route requests through a Cloudflare Worker edge function. Because the request originates from Cloudflare's own ASN, it bypasses Layer 1 IP reputation filters entirely.

### R13 — Synchronize TCP Stack & OS TTL Parameters (p0f Matching)
When scraping from a Linux VPS while claiming to be Windows 10/11, tune the Linux TCP stack (`net.ipv4.ip_default_ttl = 128`, `net.ipv4.tcp_window_scaling = 1`) to eliminate TCP SYN fingerprint mismatch (Rule R13).

### R14 — Probe Direct-to-Origin Before Complex Solving
Always run `cf_origin_finder.py` first. If the backend web server's real IP address is exposed via historical DNS or unproxied subdomains, direct connection completely bypasses Cloudflare with zero latency.

---

## 3. THE DIRECT-TO-ORIGIN BYPASS (ZERO-CHALLENGE SOLUTION)

The most elegant and reliable Cloudflare bypass is not solving challenges—it is discovering the genuine **Origin Web Server IP address** and connecting to it directly.

```
                  ┌────────────────────────────────────────┐
                  │ Target Domain: example.com             │
                  └───────────────────┬────────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
     [Normal Cloudflare Route]                    [Direct-to-Origin Route]
     https://example.com/                         https://198.51.100.25/
     ├── IP: 104.21.x.x (Cloudflare Proxy)        ├── IP: 198.51.100.25 (Real Server)
     ├── Layer 1 - 6 Inspections Active           ├── Host Header: example.com
     ├── JavaScript IUAM Challenge (5s delay)     ├── ZERO Cloudflare Inspection
     └── Rate Limiting Enforced                   └── Response: 200 OK (0ms overhead)
```

### Origin Discovery Methodology
1. **Subdomain Reconnaissance:** Unproxied (gray-clouded) DNS records: `origin.target.com`, `direct.target.com`, `cpanel.target.com`, `mail.target.com`, `dev.target.com`, `api-origin.target.com`.
2. **Certificate Transparency Logs (crt.sh):** Historical SSL certificates often list subdomains configured before Cloudflare proxying was enabled.
3. **Mail Server Headers (MX / SPF):** Email servers (`mail.target.com`) frequently share the same /24 subnet or physical IP as the web origin.
4. **Outbound Server Triggers:** If the target application allows avatar uploads via URL, webhooks, or password resets, triggering a request back to your controlled server reveals the origin's real egress IP in HTTP server logs.

### Executing Direct Connection
Once the candidate IP (e.g. `198.51.100.25`) is verified using `cf_origin_finder.py`:
```bash
# cURL with Host Header
curl -k -H "Host: example.com" https://198.51.100.25/api/data

# cURL with --resolve (forces DNS mapping)
curl --resolve example.com:443:198.51.100.25 https://example.com/api/data
```

```python
# Python requests Direct Origin
import requests

response = requests.get(
    "https://198.51.100.25/api/data",
    headers={"Host": "example.com", "User-Agent": "Mozilla/5.0..."},
    verify=False
)
```

---

## 4. MULTI-TIER ESCALATION ARCHITECTURE (TIERS 0 TO 7)

```
                                [Target URL Request]
                                         │
                                         ▼
                   [Tier -1: Direct-to-Origin Scanner]
                Origin IP found via DNS/crt.sh?
                                ├── YES ──► [Direct IP Request (0ms)]
                                └── NO (Fully Proxied)
                                         │
                                         ▼
                     [Tier 0: Cloudflare Worker Proxy]
                Traffic routed via Cloudflare ASN origin
                                ├── SUCCESS ──► [Return Clean HTML]
                                └── BLOCKED (Challenge Page)
                                         │
                                         ▼
                     [Tier 1: got-scraping (Node.js)]
                Chrome 130-136 TLS Emulation + HTTP/2
                                ├── SUCCESS ──► [Cache & Return HTML]
                                └── BLOCKED
                                         │
                                         ▼
                   [Tier 2: curl_cffi / tls-client (Python)]
                Native JA3/JA4 Impersonation
                                ├── SUCCESS ──► [Cache & Return HTML]
                                └── BLOCKED
                                         │
                                         ▼
                      [Tier 3: humanoid-js V8 VM]
                Lightweight Arithmetic Challenge Evaluator
                                ├── SUCCESS ──► [Cache & Return HTML]
                                └── BLOCKED
                                         │
                                         ▼
                    [Tier 4: Puppeteer Stealth + Aborter]
                DOM Evaluator with Image/Font Aborting
                                ├── SUCCESS ──► [Extract Cookie & Return]
                                └── BLOCKED
                                         │
                                         ▼
                   [Tier 5: Puppeteer Real Browser (PRB)]
                Singleton Browser Pool + XVFB Linux
                                ├── SUCCESS ──► [Extract Cookie & Return]
                                └── BLOCKED
                                         │
                                         ▼
                 [Tier 6: Cantarella Bypass Sidecar API]
              Rebrowser (Anti-CDP) + Ghost Cursor + Turnstile Solver
                                ├── SUCCESS ──► [Extract cf_clearance & Return]
                                └── BLOCKED (Heavy Bot Mode)
                                         │
                                         ▼
                 [Tier 7: External CAPTCHA Solver API]
              CapSolver / 2Captcha pure-HTTP token bridge
                                └── SUCCESS ──► [Inject Token & Fetch]
```

---

### Tier -1: Direct-to-Origin Bypass (`cf_origin_finder.py`)
Scans target domain across common origin subdomains and Certificate Transparency logs:
```bash
python scripts/cf_origin_finder.py --domain example.com --json
```

---

### Tier 0: Cloudflare Worker Edge Reverse Proxy (`cf_worker_proxy.js`)
Routes traffic through Cloudflare's own ASN, bypassing Layer 1 datacenter IP blocks.
```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get("url");
    if (!targetUrl) return new Response("Missing url", { status: 400 });

    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.delete("cf-connecting-ip");
    cleanHeaders.delete("cf-ray");
    cleanHeaders.delete("x-forwarded-for");
    cleanHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/133.0.0.0 Safari/537.36");

    return await fetch(targetUrl, { method: request.method, headers: cleanHeaders });
  }
};
```

---

### Tier 1: TLS Fingerprint Emulation (`got-scraping`)
Emulates Chrome 130–136 TLS extension ordering, HTTP/2 ALPN, and header casing in Node.js.

---

### Tier 2: Native JA3/JA4 Impersonation (`curl_cffi` / `tls-client`)
Python wrapper for C-based libcurl with exact binary JA3/JA4 reproduction:
```python
from curl_cffi import requests
session = requests.Session(impersonate="chrome133")
response = session.get("https://target.com")
```

---

### Tier 3: Sandboxed V8 Math Evaluator (`humanoid-js`)
Solves simple arithmetic proof-of-work in Node VM without browser process overhead.

---

### Tier 4: Optimized Puppeteer Stealth with Aggressive Resource Aborting
Launches headless Chrome, aborts images/fonts/media, and extracts cookies when challenges complete.

---

### Tier 5: Puppeteer Real Browser (PRB) with Singleton Pooling & XVFB
Manages recycled browser instances (`PRB_MAX_PAGES = 20`) on Linux headless displays with native Turnstile hooks.

---

### Tier 6: Cantarella Bypass Sidecar (Rebrowser + Ghost Cursor + CDP Patch)
Dedicated microservice running `rebrowser-puppeteer-core` (isolated `utilityWorld` to eliminate CDP leaks) and `ghost-cursor` (Fitts's Law human Bezier mouse kinematics).

---

### Tier 7: External CAPTCHA Solver Bridge (`turnstile_api_solver.py`)
Pure-HTTP fallback for extreme Enterprise Bot Management or low-memory VPS servers using CapSolver / 2Captcha APIs:
```bash
python scripts/turnstile_api_solver.py --provider capsolver --api-key "CAP-KEY" --url "https://target.com" --sitekey "0x4AAAAAA..."
```

---

## 5. ADVANCED NETWORK & OS FINGERPRINTING (TCP SYN / p0f TUNING)

Cloudflare analyzes the initial TCP SYN packet before the TLS handshake even begins (passive OS fingerprinting via p0f).

### The TCP Stack Mismatch Problem
If your HTTP `User-Agent` claims:
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...`
But your request is sent from a default Ubuntu Linux VPS:

| TCP Parameter | Default Linux Kernel | Windows 10/11 Chrome Standard | Detection Consequence |
|---|---|---|---|
| **IP Default TTL** | `64` | `128` | Instant OS Mismatch Flag |
| **TCP Window Size** | `29200` | `64240` / `65535` | Flagged as non-Windows client |
| **Window Scale Factor** | `7` | `8` | Subtle entropy indicator |
| **TCP SYN Options Order** | `MSS, SACK, TS, NOP, WScale` | `MSS, NOP, WScale, SACK, TS` | Binary stack signature mismatch |

### Tuning Linux Host TCP Stack for Windows Emulation
Run these `sysctl` commands on your Linux worker machine:
```bash
# 1. Set IP TTL to Windows default (128)
sudo sysctl -w net.ipv4.ip_default_ttl=128

# 2. Enable TCP window scaling
sudo sysctl -w net.ipv4.tcp_window_scaling=1

# 3. Disable TCP timestamps (Windows Chrome typically omits TCP timestamps)
sudo sysctl -w net.ipv4.tcp_timestamps=0

# 4. Set default TCP window buffer size
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"
sudo sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"
```

---

## 6. ENGINE-LEVEL ANTI-BOT NEUTRALIZATION (CAMOUFOX VS REBROWSER)

### Why Standard Chromium Automation is Detected
1. **CDP `Runtime.enable` Leak:** Creates `window.cdc_...` identifiers and registers V8 inspector listeners in global execution context.
2. **`navigator.webdriver` Property:** Defaults to `true`.
3. **`Function.prototype.toString` Traps:** Overriding native methods via standard JS proxies alters the bytecode length returned by `Function.prototype.toString`.

### Comparison of Advanced Engine Solutions

| Feature / Capability | Standard Puppeteer | Puppeteer Stealth | Rebrowser (Tier 6) | Camoufox (C++ Firefox) |
|---|---|---|---|---|
| **CDP Leak Neutralization** | None (Leaked) | Partial | **100% (UtilityWorld)** | **N/A (No CDP used)** |
| **Engine Level Spoofing** | None | JS Injection | JS Protocol Patch | **C++ Native Engine** |
| **CreepJS Trust Score** | 15%–30% | 45%–65% | 75%–88% | **96%–100%** |
| **Turnstile Pass Rate** | < 10% | 40%–60% | 90%–96% | **97%–99%** |
| **Resource Footprint** | ~350MB | ~380MB | ~120MB (Aborted) | ~180MB |

---

## 7. CLOUDFLARE COOKIE ANATOMY & BEHAVIORAL TRACKING (`__cf_bm`, `cf_clearance`)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Cloudflare Cookie Ecosystem                          │
├───────────────────┬───────────────────┬─────────────────────────────────┤
│ Cookie Name       │ Typical TTL       │ Purpose & Verification Role     │
├───────────────────┼───────────────────┼─────────────────────────────────┤
│ `cf_clearance`    │ 15 to 30 minutes  │ Proof of challenge completion;  │
│                   │                   │ tied to TLS JA3 + User-Agent    │
├───────────────────┼───────────────────┼─────────────────────────────────┤
│ `__cf_bm`         │ 30 minutes        │ Rolling Bot Management cookie;  │
│                   │ (re-issued)       │ tracks pacing & behavioral score│
├───────────────────┼───────────────────┼─────────────────────────────────┤
│ `__cfwaitingroom` │ 5 to 15 minutes   │ Virtual waiting room token      │
├───────────────────┼───────────────────┼─────────────────────────────────┤
│ `cf_chl_opt`      │ In-memory JS      │ Challenge config payload object │
└───────────────────┴───────────────────┴─────────────────────────────────┘
```

### The `__cf_bm` Behavioral Tracker
`__cf_bm` is updated on every asset request (JS, CSS, API calls). If requests arrive in an un-human burst (e.g. 50 parallel requests in 100ms without fetching stylesheet assets), Cloudflare elevates the bot score and revokes the `cf_clearance` token.

---

## 8. TURNSTILE EXECUTION MODES, KINEMATICS MATHEMATICS, & COORDINATE SOLVING

### Turnstile Execution Modes
1. **Managed Mode:** Cloudflare dynamically decides whether to show a passive background challenge, an interactive checkbox, or an interactive puzzle based on incoming risk score.
2. **Non-Interactive Mode:** Displays a loading spinner and solves mathematical and browser PoW in the background without user interaction.
3. **Invisible Mode:** Embedded in forms with no visual DOM presence; executes during form submission.

### Coordinate Bounding-Box Detection Algorithm (`br.ts`)
```typescript
const coordinates = await page.evaluate(() => {
  const coords: { x: number; y: number; w: number; h: number }[] = [];
  document.querySelectorAll('div').forEach(item => {
    try {
      const rect = item.getBoundingClientRect();
      const style = window.getComputedStyle(item);
      // Turnstile iframe bounding box matches 290px - 315px width with 0 padding/margin
      if (style.margin === "0px" && style.padding === "0px" && rect.width >= 290 && rect.width <= 315 && !item.querySelector('*')) {
        coords.push({ x: rect.x, y: rect.y, w: rect.width, h: rect.height });
      }
    } catch {}
  });
  return coords;
});
```

---

## 9. WEB WORKER POW CHALLENGE EXECUTION & INTROSPECTION

Cloudflare's challenge scripts often delegate heavy SHA-256 and Argon2/WASM PoW calculations to background Web Workers spawned from `blob:` URLs:
```javascript
// Introspecting Cloudflare Web Worker Challenges
const origWorker = window.Worker;
window.Worker = function(scriptUrl, options) {
  console.log('[CF-Worker] Spawning background PoW worker:', scriptUrl);
  const worker = new origWorker(scriptUrl, options);
  
  const origPost = worker.postMessage;
  worker.postMessage = function(data) {
    console.log('[CF-Worker-PoW In]', data);
    return origPost.apply(this, arguments);
  };
  
  worker.addEventListener('message', (e) => {
    console.log('[CF-Worker-PoW Out]', e.data);
  });
  
  return worker;
};
```

---

## 10. HARDWARE, SENSOR, & FONT FINGERPRINT VECTORS

| Vector | What Cloudflare Tests | Safe Configuration |
|---|---|---|
| **Battery API** | Probes `navigator.getBattery()` for non-existent battery on desktop | Return battery object or `undefined` (do not throw TypeError) |
| **Network Info** | `navigator.connection.rtt`, `downlink`, `effectiveType` | Return `rtt: 50`, `downlink: 10`, `effectiveType: '4g'` |
| **Hardware Concurrency** | Logical CPU cores (`navigator.hardwareConcurrency`) | Set to `4`, `8`, or `16` (never `0` or `1`) |
| **Device Memory** | RAM size (`navigator.deviceMemory`) | Set to `8` or `16` |
| **Font Bounding Box** | Measures sub-pixel text metrics for standard Windows fonts | Ensure real fonts (`Arial`, `Segoe UI`, `Consolas`) are installed |

---

## 11. COOKIE JAR MANAGEMENT, CACHING, & TOKEN REPLAY

```python
# cf_session.py - Production Replay Architecture
import json
import time
from pathlib import Path
from curl_cffi import requests

class CloudflareSessionManager:
    def __init__(self, storage_path="cf_sessions.json"):
        self.path = Path(storage_path)
        self.cache = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try: return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception: return {}
        return {}

    def get_session(self, domain: str) -> dict | None:
        entry = self.cache.get(domain)
        if entry and entry.get("expires_at", 0) > time.time():
            return entry
        return None

    def store_clearance(self, domain: str, cf_clearance: str, user_agent: str, ttl: int = 1500):
        self.cache[domain] = {
            "cf_clearance": cf_clearance,
            "user_agent": user_agent,
            "expires_at": time.time() + ttl
        }
        self.path.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")

    def make_request(self, url: str, domain: str) -> requests.Response:
        sess = self.get_session(domain)
        if not sess: raise ValueError(f"No valid session for {domain}")
        client = requests.Session(impersonate="chrome133")
        client.cookies.set("cf_clearance", sess["cf_clearance"], domain=domain)
        return client.get(url, headers={"User-Agent": sess["user_agent"]})
```

---

## 12. SUBPROCESS & MEMORY MANAGEMENT (PREVENTING ZOMBIE CHROMIUM)

```typescript
import kill from "tree-kill";

export function terminateProcessTree(pid: number, xvfbSession?: any, chromeInstance?: any): Promise<void> {
  return new Promise((resolve) => {
    if (xvfbSession) try { xvfbSession.stopSync(); } catch {}
    if (chromeInstance) try { chromeInstance.kill(); } catch {}
    if (pid) {
      kill(pid, "SIGKILL", (err) => {
        if (err) console.warn(`Process kill warning for PID ${pid}:`, err.message);
        resolve();
      });
    } else resolve();
  });
}
```

---

## 13. PROXY STRATEGIES & IP REPUTATION ENGINEERING

| Proxy Category | Protocol | Pass Rate | Best Architecture Tier |
|---|---|---|---|
| **Direct Origin IP** | HTTP/HTTPS | **100%** | **Tier -1 (`cf_origin_finder.py`)** |
| **Cloudflare Worker Edge** | HTTPS | **75%–90%** | **Tier 0 (`cf_worker_proxy.js`)** |
| **Datacenter Proxy** | HTTP/SOCKS5 | **25%–40%** | **Tier 1 (`got-scraping`)** |
| **Residential (Static ISP)** | HTTP/SOCKS5 | **92%–98%** | **Tier 5 & 6 (PRB / Cantarella)** |
| **Mobile 4G/5G CGNAT** | HTTP/SOCKS5 | **99.5%** | **Tier 6 & 7 (Enterprise Turnstile)** |

---

## 14. CLI TOOLSET REFERENCE & WORKFLOWS

All scripts reside in `c:\apk-reverse\apk\.agents\skills\cf-bypass\scripts\`:

| Script | Language | Primary Purpose |
|---|---|---|
| [`cf_origin_finder.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_origin_finder.py) | Python | Discover unproxied Origin Web Server IP addresses via DNS, subdomains, & crt.sh |
| [`cf_detector.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_detector.py) | Python | Scan live URLs or local HTML files for Cloudflare IUAM, Turnstile, and WAF signatures |
| [`cf_pipeline.js`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_pipeline.js) | Node.js | Multi-tier runner executing got-scraping -> Stealth -> Puppeteer pipeline |
| [`cf_worker_proxy.js`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_worker_proxy.js) | Node.js | Cloudflare Worker edge reverse proxy template for zero-server-load bypass |
| [`cf_session.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_session.py) | Python | Store, validate, and replay `cf_clearance` cookies with synchronized User-Agents |
| [`cf_cantarella_client.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_cantarella_client.py) | Python | API client for Cantarella Bypass sidecar microservice (`.cf-bypass`) |
| [`turnstile_api_solver.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/turnstile_api_solver.py) | Python | Pure-HTTP solver bridge for CapSolver & 2Captcha API integration |
| [`cf_cookie_inspector.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_cookie_inspector.py) | Python | Deep inspector for `cf_clearance` cookies and TLS fingerprint mismatch diagnostics |
| [`cf_tls_check.py`](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/scripts/cf_tls_check.py) | Python | Check and compare JA3/JA4 fingerprints across installed HTTP clients |

---

## 15. ENCYCLOPEDIC TROUBLESHOOTING MATRIX & DIAGNOSTIC FLOWCHART

```
                              [TROUBLESHOOTING FLOWCHART]

               Is HTTP Status 200 OK but HTML < 30KB with Challenge?
                                       │
                    ┌──────────────────┴──────────────────┐
                   YES                                    NO
                    │                                     │
           [IUAM / Turnstile]                     What is HTTP Status?
                    │                                     │
   ┌────────────────┴────────────────┐         ┌──────────┴──────────┐
   │                                 │         │                     │
[Solve via Tier 5 PRB]    [Solve via Tier 6]  [HTTP 403]        [HTTP 429 / 1015]
Check CDP Leaks          Use Ghost Cursor    Check JA3/UA       Rate Limited -> Rotate
Rebrowser Isolation      Check BoundingBox   Rule R1 Mismatch   Proxy or Egress IP
```

| Error / Symptom | Root Cause | Immediate Remediation |
|---|---|---|
| **HTTP 403 Forbidden on Replay** | TLS JA3 fingerprint mismatch between challenge solver (Chrome) and replay client (Python `requests` / `curl`) | Use `curl_cffi` (Python) or `got-scraping` (Node.js). Ensure `impersonate="chrome133"` and verify `User-Agent` matches byte-for-byte (Rule R1). |
| **Infinite Loop on "Just a moment..."** | Puppeteer detected via CDP `Runtime.enable` leak or missing Chromium feature flags | Switch to `rebrowser-puppeteer-core` (Tier 6) or Puppeteer Real Browser (Tier 5). Ensure resource aborting is not blocking challenge scripts. |
| **Turnstile Checkbox Re-spawns Continuously** | Mouse movement was linear/instantaneous, failing entropy checks; or IP is flagged | Implement `ghost-cursor` Bezier trajectory simulation with random hover delay. If IP is blacklisted, route through forward proxy or Tier 0 CF Worker. |
| **Server RAM Spike / Node.js Crash** | Uncontrolled Chromium process spawning or orphaned renderer zombies | Implement singleton browser pooling (`PRB_MAX_PAGES = 20`) and enforce `tree-kill(pid, 'SIGKILL')` on all process exit handlers (Rule R8). |
| **Canvas / WebGL Fingerprint Mismatch** | Headless Chrome running without display server produces blank canvas hashes | On Linux servers, ensure XVFB virtual frame buffer is active (`disableXvfb: false` in PRB). |
| **"Error 1020: Access Denied"** | Hard WAF IP block or geofencing rule | Try Direct-to-Origin bypass via `cf_origin_finder.py`. Alternatively, deploy `cf_worker_proxy.js` to Cloudflare Workers or rotate residential proxies. |
| **"Error 1015: You are being rate limited"** | Too many requests from single IP address | Implement exponential backoff jitter and rotate proxy IP pool. |
| **Turnstile Iframe Not Found in DOM** | Shadow DOM encapsulation or dynamic iframe injection delay | Use bounding-box coordinate detection loop ($290\text{px} \le \text{width} \le 315\text{px}$) from `br.ts`. |
| **`cf_clearance` Expired After 15 Minutes** | Target configured with aggressive token expiry | Implement background token refresher or proactive cache TTL invalidation at 12-minute intervals. |
| **OS Fingerprint Mismatch (p0f Flag)** | Linux host kernel TCP SYN parameters do not match Windows User-Agent | Execute Linux `sysctl` commands: `net.ipv4.ip_default_ttl=128`, `net.ipv4.tcp_window_scaling=1` (Rule R13). |
