# Webpack, Vite, & Single-Page Application (SPA) Bundle Internals

This reference guide provides an exhaustive dissection of modern JavaScript bundler runtimes (Webpack 4/5, Vite/Rollup, Turbopack, Next.js), chunk loading mechanisms, module resolution graphs, and runtime hijacking techniques for web reverse engineering.

---

## 1. Webpack 5 Runtime Architecture & Chunk Loading

Webpack compiles hundreds of modular files into bundled JavaScript chunks managed by an internal runtime.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Webpack 5 Runtime Lifecycle                     │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Bootstrap Runtime loads: window.webpackChunk<AppName> = []          │
│ 2. Array.prototype.push is intercepted with webpackJsonpCallback       │
│ 3. Asynchronous Chunks load via dynamic <script> or fetch()            │
│ 4. Module definitions are registered in the global installedModules map│
│ 5. Entry point module is executed via __webpack_require__(entryModule) │
└────────────────────────────────────────────────────────────────────────┘
```

### Anatomy of a Webpack 5 Chunk:
```javascript
(self["webpackChunkmy_spa"] = self["webpackChunkmy_spa"] || []).push([
  ["chunk_admin_dashboard"], // Chunk ID
  {
    // Module ID: Module Factory Function
    "./src/api/auth.ts": function(module, exports, __webpack_require__) {
      "use strict";
      const crypto = __webpack_require__("./src/utils/crypto.ts");
      exports.login = function(user, pass) { ... };
    },
    "./src/utils/crypto.ts": function(module, exports, __webpack_require__) {
      "use strict";
      exports.sign = function(data) { ... };
    }
  }
]);
```

---

## 2. Runtime Hijacking: Extracting `__webpack_require__`

In modern Webpack applications, you can gain complete programmatic access to all private internal modules directly from the browser DevTools Console by pushing a hook into the global chunk array:

```javascript
// Universal Webpack Runtime Hijack Snippet
(function() {
  let webpackRequire = null;

  // Find the global Webpack chunk array on window / self
  const chunkArrays = Object.keys(window).filter(k => k.startsWith('webpackChunk'));
  
  if (chunkArrays.length > 0) {
    const chunkName = chunkArrays[0];
    window[chunkName].push([
      ['__inspect_hook__'],
      {},
      function(req) { webpackRequire = req; }
    ]);
  }

  if (webpackRequire) {
    console.log('%c[Webpack Hijack]%c Successfully extracted __webpack_require__!', 'color: #00ffaa; font-weight: bold;', 'color: auto;');
    window.__wpReq = webpackRequire;
    
    // Inspect all available module IDs in the cache
    console.log('Installed Modules:', Object.keys(webpackRequire.c));
    console.log('Use window.__wpReq(moduleId) to call any module directly!');
  } else {
    console.warn('[Webpack Hijack] Could not hook Webpack runtime.');
  }
})();
```

Once `window.__wpReq` is available in the console, you can execute internal cryptographic or authentication functions directly:
```javascript
// Call the internal crypto module directly in the console!
const cryptoModule = window.__wpReq("./src/utils/crypto.ts");
console.log("Generated Signature:", cryptoModule.sign("test payload"));
```

---

## 3. Vite & Rollup Native ES Modules (ESM)

Unlike Webpack, which wraps code in module factory functions, Vite and Rollup use native browser ES Modules in modern builds:

```html
<!-- Vite Entry Point -->
<script type="module" crossorigin src="/assets/index-B4x_8k.js"></script>
```

### Module Structure in Vite Chunks:
```javascript
// /assets/index-B4x_8k.js
import { e as encryptPayload, s as secretKey } from "./vendor-D9a_1m.js";

function handleLogin(username, password) {
  const token = encryptPayload(username + ":" + password, secretKey);
  return fetch("/api/login", { headers: { "X-Token": token } });
}
export { handleLogin };
```

### Reverse Engineering Vite / Rollup Bundles:
- Vite bundles do not have a centralized `__webpack_require__` map.
- To inspect modules, use `scripts/js_deobfuscator.py` to format the chunk, and follow native `import` statements between chunk files in the `assets/` directory.

---

## 4. Next.js & Nuxt Server-Side Rendering (SSR) Hydration Payloads

Next.js and Nuxt applications embed initial server-side data directly inside static HTML:

### Next.js (`__NEXT_DATA__`):
```html
<script id="__NEXT_DATA__" type="application/json">
{
  "props": {
    "pageProps": {
      "user": { "id": 123, "role": "admin" },
      "apiEndpoint": "https://internal-api.example.com",
      "featureFlags": { "betaAccess": true }
    }
  },
  "page": "/dashboard",
  "query": {},
  "buildId": "v8a7b6c5d4"
}
</script>
```

### Instant Extraction in Console:
```javascript
const nextData = JSON.parse(document.getElementById('__NEXT_DATA__').textContent);
console.log("Next.js Server Hydration Data:", nextData);
```
