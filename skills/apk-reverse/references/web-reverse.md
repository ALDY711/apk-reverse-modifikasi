# Web Reverse Engineering — Source Maps, JS Deobfuscation & API Signatures

**Load this when**: the target is a web application, Single Page App (SPA), mobile WebView, or you need to recover original source code from `.js.map` Source Maps, deobfuscate JavaScript, trace dynamic API signatures and tokens, or patch client-side runtime behavior.

**What this answers**: how to discover and unpack Source Maps to recover complete source trees, trace client-side signature generation (e.g. `X-Sign`, `_signature`, `token`), locate request interceptors, neutralize anti-debugging traps, and deploy live userscript monkey-patches or Map-Local interceptors.

---

## 1. Source Code Recovery via Source Maps (.js.map)

### Source Map Mechanism
Production bundlers (Webpack, Vite, Rollup, esbuild, Next.js, Turbopack) transpile and minify original source code (TypeScript, JSX, Vue, SCSS) into compacted JavaScript bundles (`app.min.js`).

To aid error reporting services (Sentry, Datadog, Bugsnag), build pipelines generate **Source Map v3** files (`.js.map`). When these files or inline data URIs are exposed in production environments, **the entire unminified source code can be fully recovered**.

### Source Map v3 Structure
```json
{
  "version": 3,
  "file": "bundle.js",
  "sources": [
    "webpack:///src/api/auth.ts",
    "webpack:///src/components/PaymentModal.vue"
  ],
  "sourcesContent": [
    "export const login = (user, pass) => { ... }",
    "<template><div>...</div></template>"
  ],
  "mappings": "AAAA,SAASA..."
}
```
The `sourcesContent` array stores the original source code verbatim, including comments, internal type interfaces, and developer-authored API routes.

### Automation via `sourcemap_extractor.py`
Use [sourcemap_extractor.py](file:///c:/apk-reverse/apk-reverse/skills/apk-reverse/scripts/sourcemap_extractor.py) to scan, download, and reconstruct the project hierarchy on disk:

```bash
# 1. Spider page script tags and extract source tree
python skills/apk-reverse/scripts/sourcemap_extractor.py --url https://example.com --out-dir ./extracted_src

# 2. Extract directly from a specific bundle URL
python skills/apk-reverse/scripts/sourcemap_extractor.py --js-url https://example.com/static/js/main.chunk.js --out-dir ./src

# 3. Extract from local .js or .js.map file
python skills/apk-reverse/scripts/sourcemap_extractor.py --file app.bundle.js.map --out-dir ./src

# 4. Scan-only mode (returns JSON metadata without writing files)
python skills/apk-reverse/scripts/sourcemap_extractor.py --url https://example.com --scan-only --json
```

---

## 2. API Signatures & Dynamic Token Analysis

Modern Single Page Applications and hybrid WebViews protect endpoints against automated interaction using client-calculated signatures.

### Signature Architecture
Signatures are typically constructed from request attributes:
$$\text{Signature} = \text{Hash}(\text{Path} + \text{Query/Body} + \text{Timestamp} + \text{Nonce} + \text{Secret Salt})$$

Common injection targets:
* Custom HTTP Headers: `X-Sign`, `X-Signature`, `X-Timestamp`, `X-Nonce`, `X-Auth-Token`
* URL Query Parameters: `_sig`, `sign`, `token`, `t`, `nonce`
* Bearer Tokens and JWT claims embedded in runtime configurations

### Request Interceptors
Signature generation logic is nearly always concentrated in HTTP client interceptors:
1. **Axios Interceptors**:
   ```javascript
   axios.interceptors.request.use(config => {
       const timestamp = Date.now();
       const sign = calculateSign(config.url, config.data, timestamp);
       config.headers['X-Sign'] = sign;
       config.headers['X-Timestamp'] = timestamp;
       return config;
   });
   ```
2. **Fetch API & WebSocket Wrappers**:
   Custom wrappers around `window.fetch` or `new WebSocket` that inject authorization parameters before dispatch.

### Automation via `web_api_tracer.py`
Use [web_api_tracer.py](file:///c:/apk-reverse/apk-reverse/skills/apk-reverse/scripts/web_api_tracer.py) to pinpoint signature routines, cryptographic algorithms, and endpoints:

```bash
# Scan a local JavaScript bundle
python skills/apk-reverse/scripts/web_api_tracer.py --file bundle.js

# Inspect a remote bundle directly from URL
python skills/apk-reverse/scripts/web_api_tracer.py --url https://example.com/static/js/app.js

# Query for specific header or function identifier
python skills/apk-reverse/scripts/web_api_tracer.py --file bundle.js --query "X-Sign"

# Output structured JSON report
python skills/apk-reverse/scripts/web_api_tracer.py --file bundle.js --json
```

---

## 3. Replicating Client Signatures in Python / Node.js

Once the hashing routine is isolated using [web_api_tracer.py](file:///c:/apk-reverse/apk-reverse/skills/apk-reverse/scripts/web_api_tracer.py):

### Pure Re-implementation (MD5 / SHA-256 / HMAC)
If standard primitives are identified, rewrite the hashing logic in Python:
```python
import hashlib
import time

def generate_signature(path: str, body: str, secret_salt: str = "app_secret") -> dict:
    ts = str(int(time.time() * 1000))
    raw = f"{path}&{body}&{ts}&{secret_salt}"
    sign = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    return {
        "X-Sign": sign,
        "X-Timestamp": ts
    }
```

### Complex / Heavily Obfuscated Routines (RPC / Headless Evaluation)
When logic incorporates custom state machines or WebAssembly:
1. Slice the signature generator into a standalone module (`sign.js`).
2. Invoke it directly via Node.js or an RPC bridge:
   ```bash
   node -e "const { sign } = require('./sign.js'); console.log(sign('/api/v1/user', 'payload'));"
   ```

---

## 4. Automated JavaScript Deobfuscation & Anti-Debug Neutralization

When JavaScript bundles deploy anti-analysis defenses:

### `js_deobfuscator.py` Capabilities
* **Dean Edwards Unpacker**: Recursively resolves `eval(function(p,a,c,k,e,r)...)` wrappers.
* **String Escape Decoding**: Translates hex (`\x68\x65\x6c\x6c\x6f`) and unicode (`\u0041`) sequences.
* **Anti-Debugging Neutralization**: Removes `setInterval(..., debugger)`, `Function("debugger")()`, and standalone `debugger;` halts that freeze DevTools.
* **Deterministic Formatting**: Beautifies minified code with correct block indentations without Node.js dependencies.

```bash
# Deobfuscate and format JavaScript bundle
python apk_cli.py web deobf --file bundle.min.js --output bundle.clean.js

# Strip anti-debugging halts and format
python apk_cli.py web deobf --file protected.js --output clean.js
```

---

## 5. Live Web Modification & Interception

When modifying client-side logic on live targets:

### A. Userscript Generator (Tampermonkey / Violentmonkey)
Use [web_modifier.py](file:///c:/apk-reverse/apk-reverse/skills/apk-reverse/scripts/web_modifier.py) to compile tested `.user.js` scripts:

```bash
# 1. Bypass anti-debugging & re-enable right-click/context menus
python apk_cli.py web userscript --domain example.com --template bypass-anti-debug --output bypass.user.js

# 2. Hook Fetch and XHR to monitor or modify network requests
python apk_cli.py web userscript --domain example.com --template hook-api --output hook.user.js

# 3. Unlock disabled DOM elements, remove paywall backdrops, and accelerate timers
python apk_cli.py web userscript --domain example.com --template dom-unlock --output unlock.user.js

# 4. Monkey-patch specific client functions
python apk_cli.py web userscript --domain example.com --template override-func \
    --func "window.checkPermission" --return-val "true" --output override.user.js
```

### B. Map-Local HTTP Proxy Interceptor
Substitute remote JavaScript files with modified local files in real time:
```bash
# Start local Map-Local proxy server
python apk_cli.py web serve --port 8080 --map-local "/static/js/app.js=./bundle.clean.js"
```

---

## 6. Unified CLI Reference

All web reverse engineering routines are accessible via `python apk_cli.py web <subcommand>`:

| Subcommand | Script | Capability |
|---|---|---|
| `web sourcemap` | `sourcemap_extractor.py` | Reconstruct original source files from Source Maps (`.js.map`) |
| `web api-tracer` | `web_api_tracer.py` | Trace `X-Sign`, tokens, timestamps, JWTs, and crypto algorithms |
| `web deobf` | `js_deobfuscator.py` | Unpack Dean Edwards, decode hex/unicode, neutralize debuggers, format JS |
| `web userscript` | `web_modifier.py` | Generate Tampermonkey userscripts for runtime monkey-patching |
| `web serve` | `web_modifier.py` | Run local Map-Local HTTP proxy to replace remote scripts |
| `scan leaks` | `scan_leaks.py` | Scan files for API tokens, secret keys, or private endpoints |
| `scan tls` | `tls_check.py` | Audit SSL/TLS certificates and host pinning configurations |
