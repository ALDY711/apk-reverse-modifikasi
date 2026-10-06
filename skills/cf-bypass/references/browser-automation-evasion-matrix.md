# Browser Automation & Anti-Detect Framework Evasion Matrix

This technical reference provides an architectural comparison, implementation patterns, and evasion mechanics for all modern headless browser automation engines used to bypass Cloudflare Bot Management and Turnstile.

---

## 1. The Automation Detection Landscape

Modern anti-bot systems detect automation at three levels:
1. **JavaScript Environment Level:** Probing `navigator.webdriver`, `window.chrome`, `window.cdc_...` identifiers, and prototype modifications.
2. **Chrome DevTools Protocol (CDP) Level:** Detecting when the browser engine enters inspection mode via `Runtime.enable`, which exposes internal V8 debugger hooks.
3. **Behavioral & Kinematics Level:** Measuring mouse movement entropy, scroll physics, and interaction cadence.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Anti-Detect Engine Matrix                       │
├──────────────────────┬─────────────┬───────────┬───────────┬───────────┤
│ Engine / Framework   │ CDP Leaks?  │ CreepJS   │ Turnstile │ RAM / Tab │
├──────────────────────┼─────────────┼───────────┼───────────┼───────────┤
│ Standard Puppeteer   │ LEAKED      │ 15%–30%   │ < 10%     │ ~350MB    │
│ Puppeteer Stealth    │ LEAKED      │ 45%–65%   │ 40%–60%   │ ~380MB    │
│ Puppeteer Real (PRB) │ PARTIAL     │ 70%–82%   │ 85%–92%   │ ~300MB    │
│ Rebrowser (Core)     │ PATCHED     │ 85%–92%   │ 92%–96%   │ ~120MB*   │
│ Camoufox (C++ Engine)│ ZERO LEAK   │ 96%–100%  │ 97%–99.5% │ ~180MB    │
│ Patchright (PW Core) │ PATCHED     │ 88%–94%   │ 92%–96%   │ ~220MB    │
└──────────────────────┴─────────────┴───────────┴───────────┴───────────┘
* With aggressive resource aborting (Rule R5).
```

---

## 2. Rebrowser (`rebrowser-puppeteer-core`) — The CDP Fix

### The Problem it Solves:
Standard Puppeteer attaches to pages by issuing `Runtime.enable` to the default V8 execution context. This dispatch triggers events in the page's event loop that Cloudflare Turnstile actively monitors.

### How Rebrowser Eliminates the Leak:
Rebrowser executes automation commands inside an isolated `utilityWorld` (the same hidden execution environment used by Chrome browser extensions). Page-level scripts running in the main world cannot access, probe, or detect objects residing in the utility world.

### Rebrowser Implementation Pattern:
```typescript
import { launch } from 'rebrowser-puppeteer-core';

export async function createRebrowserSession(targetUrl: string) {
  const browser = await launch({
    headless: false, // or 'new'
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
    ],
  });

  const page = await browser.newPage();
  
  // Rebrowser runs all evaluate() calls in isolated utilityWorld
  await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
  return { browser, page };
}
```

---

## 3. Camoufox — C++ Engine-Level Firefox Stealth

### The Problem it Solves:
Most anti-detect tools use JavaScript `Object.defineProperty` to modify properties like `navigator.webdriver` or `navigator.plugins`.
Sophisticated WAF scripts detect this by checking `Function.prototype.toString` or calling `Object.getOwnPropertyDescriptor()` on prototypes.

### The Camoufox C++ Solution:
Camoufox modifies the C++ source code of the Firefox browser engine (Gecko):
- All fingerprint spoofing occurs natively inside C++ binaries (`GeckoChildProcessHost`, `nsContentUtils`).
- JavaScript reflection reveals **100% native bytecode** with zero wrapper proxies.
- No Chrome DevTools Protocol exists, rendering CDP-based detection completely useless.

### Camoufox Python Pattern:
```python
from camoufox.sync_api import Camoufox

with Camoufox(headless=True, os="windows") as browser:
    page = browser.new_page()
    page.goto("https://target.com")
    
    # Wait for Turnstile to automatically solve natively
    page.wait_for_selector(".content-ready", timeout=30000)
    html = page.content()
    print("Fetched via Camoufox! HTML Size:", len(html))
```

---

## 4. Puppeteer Real Browser (PRB) Architecture

PRB pairs Chromium with modified startup binaries and automated Turnstile clickers.

### Key Capabilities:
1. Automatically resolves native Chrome binaries across Linux, Windows, and NixOS.
2. Embeds an automatic Turnstile solving loop that detects checkboxes and applies simulated clicks.
3. Automatically manages Linux XVFB displays when running in headless environments.

### Implementation Blueprint:
```typescript
import { connect } from 'puppeteer-real-browser';

export async function runPRB(targetUrl: string, proxyConfig?: any) {
  const { browser, page } = await connect({
    headless: 'auto',
    turnstile: true,
    disableXvfb: false,
    proxy: proxyConfig,
    args: ['--no-sandbox', '--disable-gpu'],
  });

  await page.goto(targetUrl, { waitUntil: 'networkidle2' });
  const content = await page.content();
  await browser.close();
  return content;
}
```
