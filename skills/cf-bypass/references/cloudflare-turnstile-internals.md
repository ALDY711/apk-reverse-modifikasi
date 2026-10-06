# Cloudflare Turnstile Internals & Challenge Platform Deep Dive

This reference document provides an exhaustive technical analysis of Cloudflare's Challenge Platform, Turnstile widget lifecycle, client-side proof-of-work (PoW) algorithms, iframe DOM architecture, and token issuance mechanics.

---

## 1. Cloudflare Challenge Platform Architecture

Cloudflare protects websites using the **Challenge Platform** (formerly known as IUAM or "I'm Under Attack Mode", now modernized with Turnstile).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Cloudflare Edge Ingestion                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              Browser Navigation / Protected Asset Request              │
│                 GET /login -> Cloudflare Edge Proxy                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Returns 403 / 503 or HTML Challenge
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     HTML Challenge Host Page (<20KB)                   │
│  ├── <script src="/cdn-cgi/challenge-platform/h/g/orchestrate/..."/>   │
│  ├── <script>window._cf_chl_opt = { cRay: '...', cHash: '...' }</script>│
│  └── <div id="turnstile-wrapper"> (Iframe Container)                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Orchestrator executes
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Turnstile Isolated Iframe Sandbox                    │
│   src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform...│
│  ├── Canvas 2D & WebGL driver capability benchmarks                   │
│  ├── Hardware concurrency, device memory, battery API probes           │
│  ├── Chrome DevTools Protocol (CDP) detection probes                   │
│  ├── Mouse movement dynamics (entropy, curvature, Bezier acceleration) │
│  └── Background Web Worker PoW (SHA-256 / Argon2 / WASM)              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Post solved payload (JSON/Encrypted)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               POST /cdn-cgi/challenge-platform/h/g/flow/ov1/...        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
      [VALIDATION SUCCESS]                [VALIDATION FAILURE]
  ├── Set-Cookie: cf_clearance=...   ├── Re-spawn interactive Turnstile
  ├── Token: cf-turnstile-response   └── HTTP 403 Forbidden / Loop
  └── Location: /login (200 OK)
```

---

## 2. Window Scope Challenge Configuration (`window._cf_chl_opt`)

When a Cloudflare challenge page is rendered, the HTML source contains an in-memory configuration object:

```javascript
window._cf_chl_opt = {
  cRay: '91234abcd5678ef0',          // Cloudflare Ray ID for the request
  cHash: 'a1b2c3d4e5f60718',         // Hash of the target zone rule
  cUPMDTk: "\/login?__cf_chl_tk=...",// Verification callback URI
  cFPWv: 'g',                         // Fingerprint worker variant ('g' = general, 'b' = bot)
  cITimeS: '1741165200',              // Challenge initiation timestamp
  cTTimeMs: '1000',                   // Minimum challenge display duration in ms
  cMTimeMs: '15000',                  // Challenge timeout limit
  chlApiMode: 'managed',              // 'managed', 'non-interactive', or 'invisible'
  chlApiWidgetId: '0.123456789',      // Unique Turnstile widget ID
  chlApiSitekey: '0x4AAAAAAABcd12345' // Turnstile sitekey
};
```

### Critical Parameters for Analysts:
- `cRay`: Unique identifier for the transaction. If replaying requests, logging this Ray ID helps trace whether Cloudflare rejected or accepted the token.
- `chlApiMode`: Defines whether human user interaction (clicking the checkbox) is mandatory or if background JavaScript evaluation is sufficient.

---

## 3. Turnstile Iframe DOM Structure & Bounding Box Heuristics

Turnstile injects an iframe hosted on `challenges.cloudflare.com`.

### Characteristic Bounding Box & CSS Attributes
- **Width:** Exactly $300\text{px}$ (acceptable tolerance: $290\text{px} \le \text{width} \le 315\text{px}$).
- **Height:** Exactly $65\text{px}$ (acceptable tolerance: $60\text{px} \le \text{height} \le 75\text{px}$).
- **Margin & Padding:** `0px`.
- **Border:** `none` (or minimal border).
- **Target Checkbox Offset:** The clickable target (the square checkbox icon) is positioned at approximately $X + 30\text{px}$ from the left edge and $Y + \text{height}/2$ vertically.

```
┌─────────────────────────────────────────────────────────────┐
│ (x, y)                                            w=300px   │
│   ┌──────┐                                                  │
│   │ [✓]  │  Verify you are human                            │
│   └──────┘                                                  │
│    (x+30, y+32)                          h=65px             │
│                                           Cloudflare Logo   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Turnstile Behavioral Kinematics & Entropy Verification

Cloudflare evaluates client-side mouse and touch event sequences captured while the user hovers over and clicks the widget.

### Evaluated Heuristic Signals
1. **Trajectory Linearity (Curvature Entropy):**
   Synthetic bots move mouse coordinates in a straight line:
   $$x(t) = x_0 + t(x_1 - x_0), \quad y(t) = y_0 + t(y_1 - y_0)$$
   Straight lines produce zero curvature entropy and trigger immediate failure.
2. **Acceleration & Jerk Derivative:**
   Human muscle movement exhibits variable acceleration with natural deceleration (damping) as the pointer nears the target (Fitts's Law).
3. **Sub-pixel Tremor & Micro-overshoot:**
   Human operators routinely overshoot the target by 2–8 pixels before correcting, producing micro-movements with slight coordinate jitter.
4. **Hover Dwell Time:**
   The duration between reaching the checkbox bounding box and firing `mousedown` must fall within normal human cognitive reaction limits ($80\text{ms} \le t_{\text{dwell}} \le 350\text{ms}$). Instant clicks (<10ms) are flagged.

---

## 5. Token Issuance & Form Injection Protocol

Upon successful verification, Turnstile generates a single-use token:

```
Token Format: 0.abc123DEF456... (Alphanumeric string, 200–600 characters)
Lifetime: 300 seconds (5 minutes)
```

### How the Token is Applied:
1. **Hidden Form Input:**
   Turnstile automatically inserts or populates an input field:
   ```html
   <input type="hidden" name="cf-turnstile-response" value="0.abc123DEF456...">
   ```
2. **JavaScript Callback:**
   If a callback was registered in `turnstile.render()`, Cloudflare invokes:
   ```javascript
   window.tsCallback("0.abc123DEF456...");
   ```
3. **Header Transmission:**
   Single-Page Applications attach the token as an HTTP header:
   ```http
   X-Turnstile-Token: 0.abc123DEF456...
   ```

---

## 6. Token Verification at the Origin Server

The origin server validates the token by making a backend HTTP POST to Cloudflare:

```http
POST https://challenges.cloudflare.com/turnstile/v0/siteverify HTTP/1.1
Content-Type: application/json

{
  "secret": "0x4AAAAAAABcdSecretKey12345",
  "response": "0.abc123DEF456...",
  "remoteip": "203.0.113.195"
}
```

Cloudflare returns JSON:
```json
{
  "success": true,
  "challenge_ts": "2026-10-06T02:15:00.000Z",
  "hostname": "example.com",
  "error-codes": [],
  "action": "login",
  "cdata": ""
}
```

If `remoteip` was supplied by the origin server and does NOT match the IP address that solved the challenge, Cloudflare returns `"success": false` with error `"invalid-remoteip"`. This is why **IP address coherence** between solver and requester is mandatory.
