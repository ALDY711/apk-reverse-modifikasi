---
name: web-reverse
description: "Reverse engineer, deobfuscate, unpack, and analyze client-side web applications, single-page apps (SPA: React, Vue, Angular, Next.js), Webpack/Vite bundles, and WebSocket/REST APIs. Features Source Map v3 recovery, AST/eval unpacking, anti-debugging neutralization, dynamic runtime hooking, API signature tracing, WebAssembly analysis, and live DOM/traffic modification."
license: MIT
compatibility: "Python 3.9+, Node.js 18+. Browser: Chrome/Edge/Firefox with DevTools, Tampermonkey/Violentmonkey. Proxy: mitmproxy, Charles, Proxyman, Whistle."
metadata:
  version: "2.0"
  reference_tools:
    - "scripts/sourcemap_extractor.py"
    - "scripts/webpack_unpacker.py"
    - "scripts/js_deobfuscator.py"
    - "scripts/web_api_tracer.py"
    - "scripts/devtools_hook_generator.py"
    - "scripts/ws_inspector.py"
    - "scripts/web_modifier.py"
    - "scripts/har_analyzer.py"
  last_reconstruction_pass: "2026-10-05"
---

# Web Application Reverse Engineering & Analysis — Panduan Komprehensif

Skill ini adalah manual operasional tingkat lanjut untuk membongkar, menganalisis, melakukan deobfuscation, merekonstruksi source code asli, melacak algoritma signature/token API, dan memodifikasi alur logika JavaScript pada aplikasi web modern, Single-Page Application (SPA: React, Vue, Next.js, Nuxt, Svelte, Angular), WebAssembly (WASM), serta antarmuka WebView seluler.

Aplikasi web modern tidak lagi berupa file HTML statis sederhana. Mereka adalah sistem terdistribusi kompleks yang dikompilasi, diminifikasi, di-chunk, dan sering kali diproteksi dengan teknik anti-analisis, kontrol integritas request, enkripsi payload, dan anti-debugging. Panduan ini memberikan metodologi lengkap dari tahap awal inspeksi hingga penulisan skrip replay otomatis.

---

## DAFTAR ISI

1. [Aturan Kritis (Critical Rules R1 - R8)](#aturan-kritis-critical-rules-r1---r8)
2. [Arsitektur & Mental Model Web Modern](#arsitektur--mental-model-web-modern)
   - Anatomi Webpack (v4 vs v5, Chunks, Runtime `__webpack_require__`)
   - Vite & ES Modules (Rollup Chunking)
   - Framework SSR (Next.js `__NEXT_DATA__`, Nuxt, SvelteKit)
3. [Alur Kerja Investigasi Lengkap (End-to-End Workflow)](#alur-kerja-investigasi-lengkap-end-to-end-workflow)
4. [Teknik Rekonstruksi Kode Sumber (Source Recovery)](#teknik-rekonstruksi-kode-sumber-source-recovery)
   - Source Map v3 Discovery & VLQ Extraction
   - Webpack Chunk Disassembly & Module Extraction
5. [Deobfuscation & AST Unravelling](#deobfuscation--ast-unravelling)
   - Unpacking Dean Edwards (`eval(function(p,a,c,k,e,d)...)`)
   - String Array Obfuscation (Array + Shift + Decryptor Function)
   - Control Flow Flattening (Switch-Case Loops)
   - Dead Code Elimination & Opaque Predicates
   - Member Expression Normalization (`window['\x61\x74\x6f\x62']`)
6. [Netralisasi Anti-Debugging & Proteksi DevTools](#netralisasi-anti-debugging--proteksi-devtools)
   - Infinite Loop `debugger;` & `Function("debugger")()`
   - Timing Checks (`performance.now`, `Date.now`)
   - Console Poisoning & DevTools Dimension Sniffing
   - Strategi Bypass: Userscript (`@run-at document-start`), DevTools Snippet, Local Overrides
7. [Reverse Engineering API Signature & Enkripsi Payload](#reverse-engineering-api-signature--enkripsi-payload)
   - Struktur Request Signing (`X-Sign`, `nonce`, `timestamp`, `token`)
   - Metodologi Pelacakan Data-Flow (XHR Breakpoint, Event Breakpoint, Call Stack)
   - Ekstraksi Secret Key, Salt, dan Algoritma (MD5, HMAC-SHA256, AES-CBC/GCM)
   - Replay Request via Python (`requests`, `curl_cffi`) atau Node.js (`got-scraping`)
8. [Reverse Engineering WebAssembly (WASM) & Worker Threads](#reverse-engineering-webassembly-wasm--worker-threads)
   - Deteksi Komputasi WASM & Web Worker
   - Ekstraksi `.wasm`, Konversi ke `.wat` via `wasm2wat`, Decompilation
   - Hooking Jembatan JS-WASM (`WebAssembly.instantiate`, exports)
9. [Analisis Protokol Real-Time (WebSocket & SSE)](#analisis-protokol-real-time-websocket--sse)
   - Hooking `WebSocket.prototype.send` dan `onmessage`
   - Decoding Frame Protobuf Biner Tanpa Schema `.proto`
   - Decoding Frame Socket.IO (Engine.IO Packet Hierarchy) & JSON-RPC
10. [Modifikasi Runtime & Live Overrides](#modifikasi-runtime--live-overrides)
    - Chrome/Edge DevTools Local Overrides
    - Map-Local / Map-Remote via Proxy (mitmproxy, Charles, Proxyman)
    - Userscript Injection (Tampermonkey/Violentmonkey) dengan Proxy Traps
11. [Katalog Tools & Skrip Helper](#katalog-tools--skrip-helper)
12. [Troubleshooting & Symptom Index](#troubleshooting--symptom-index)

---

## ATURAN KRITIS (CRITICAL RULES R1 - R8)

Setiap aturan di bawah ini dibuat dari kegagalan nyata yang membuang puluhan jam kerja saat menganalisis target yang diproteksi.

### R1 — Source Map v3 Selalu Menjadi Prioritas Nomor Satu

Jangan pernah membuang waktu menganalisis 100.000 baris kode JavaScript minified sebelum memeriksa keberadaan Source Map (`.js.map`).
- Sekitar 25-35% situs web di internet secara tidak sengaja membiarkan file `.map` dapat diakses publik di server produksi (atau tertinggal dalam format inline Base64 data URI).
- Jika file `.js.map` ditemukan, Anda mendapatkan **100% source code asli**: file TypeScript (`.ts`), React JSX (`.tsx`), Vue SFC (`.vue`), komentar developer, nama variabel asli, nama fungsi asli, dan struktur folder proyek lengkap.
- **Tindakan Wajib:** Jalankan `python scripts/sourcemap_extractor.py --url <TARGET_URL>` sebelum melakukan analisis manual apapun.

### R2 — Netralisasi Anti-Debugging Harus Aktif Sejak `document-start`

Jika target menggunakan script anti-debugging (misalnya loop `Function("debugger")()` di dalam `setInterval` setiap 50ms):
- Membuka DevTools saat halaman sudah berjalan akan langsung membekukan browser tab.
- Memasang hook di console DevTools setelah halaman selesai dimuat **sudah terlambat** karena loop timer sudah aktif di background thread.
- **Tindakan Wajib:** Pasang Userscript (Tampermonkey/Violentmonkey) dengan metadata `@run-at document-start` menggunakan `scripts/devtools_hook_generator.py` agar fungsi `Function`, `eval`, dan timer di-proxy sebelum script target dieksekusi oleh browser engine.

### R3 — Jangan Analisis Kode Terkompresi Secara Mentah

Membaca bundle 5MB dalam satu baris (single-line minified) adalah penyebab utama kesalahan asumsi.
- Minifier seperti Terser atau esbuild menggabungkan ekspresi menggunakan operator koma (`,`), mengubah `if-else` menjadi ternary (`? :`), serta mengganti nama semua variabel lokal menjadi satu karakter (`a`, `b`, `c`).
- **Tindakan Wajib:**
  1. Pecah bundle menjadi modul individual dengan `scripts/webpack_unpacker.py`.
  2. Format dan deobfuscate modul yang relevan dengan `scripts/js_deobfuscator.py`.

### R4 — Lacak Signature Melalui Data-Flow, Bukan Menebak-nebak

Ketika menemukan header seperti `X-Sign: 8f2a1b9e...`, jangan langsung menebak apakah itu MD5 atau SHA256 hanya dari panjang karakternya.
- Request signature di client-side hampir selalu melibatkan pengurutan parameter (canonical query string), penambahan timestamp, nonce acak, dan penggabungan dengan secret key atau token sesi.
- **Tindakan Wajib:**
  1. Pasang XHR/Fetch Breakpoint di DevTools pada URL endpoint target, atau gunakan `scripts/devtools_hook_generator.py --mode fetch-xhr`.
  2. Saat breakpoint terpukul, periksa **Call Stack** ke belakang (naik 2-4 frame). Di situlah interceptor Axios atau fungsi pembuat signature berada.

### R5 — Perlakukan Webpack Runtime Secara Holistik

Aplikasi React/Vue modern memisahkan bundle menjadi:
- `runtime~main.js` (Webpack bootstrap & dynamic chunk loader).
- `vendor.js` (library pihak ketiga: React, Axios, CryptoJS).
- `app.js` atau `[id].[hash].chunk.js` (kode bisnis & API handler).
- Jangan menganalisis satu chunk tanpa memahami bagaimana chunk tersebut di-load oleh runtime. Webpack menyimpan daftar modul di array global (`window.webpackChunk...` atau `window.webpackJsonp`).

### R6 — Awasi WebAssembly (WASM) dan Web Workers

Jika pencarian string untuk algoritma kriptografi (MD5, AES, HMAC) di semua file `.js` tidak membuahkan hasil, tetapi data keluar dalam bentuk ciphertext atau hash:
- Hashing kemungkinan besar dikompilasi ke dalam WebAssembly (`.wasm`) dari C/C++/Rust/Go, atau dijalankan di Web Worker terpisah agar tidak memblokir UI thread.
- **Tindakan Wajib:** Periksa tab **Sources** -> **Wasm** di DevTools, dan periksa network filter untuk file biner `.wasm`. Hook fungsi `WebAssembly.instantiate` untuk memantau buffer yang di-load.

### R7 — Replay Request Harus Sinkron dengan Fingerprint & Header

Saat mereproduksi request API di Python:
- Header `User-Agent`, `Accept`, `Accept-Language`, `Origin`, dan `Referer` harus identik dengan yang dikirim oleh browser asli.
- Urutan query parameter dan struktur JSON body harus persis sama (beberapa backend menolak request jika kunci JSON tidak terurut sesuai algoritma penandatanganan).
- Jika target dilindungi Cloudflare / Akamai / Datadome, gunakan library yang mendukung impersonasi TLS fingerprint seperti `curl_cffi` atau `got-scraping` (rujuk skill [cf-bypass](file:///c:/apk-reverse/apk/.agents/skills/cf-bypass/SKILL.md)).

### R8 — Waspadai Dynamic Code Injection (`eval`, `new Function`, Blob URL)

Beberapa sistem anti-bot atau skrip terobfuskasi memuat logika sensitif secara dinamis:
- Mengambil string terenkripsi dari server, mendekripsinya di runtime, lalu mengeksekusinya via `eval()` atau `new Function()`.
- Membuat Web Worker dari `URL.createObjectURL(new Blob([...]))`.
- **Tindakan Wajib:** Selalu hook `window.eval`, `window.Function`, dan `URL.createObjectURL` agar payload dinamis dapat langsung ditangkap dan disimpan ke disk.

---

## ARSITEKTUR & MENTAL MODEL WEB MODERN

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           BROWSER RUNTIME                               │
├─────────────────────────────────────────────────────────────────────────┤
│  DOM / BOM Environment (window, document, navigator, location)           │
│                                                                         │
│  ┌───────────────────────────┐      ┌────────────────────────────────┐  │
│  │    Webpack / Vite Bundle  │      │     WebAssembly (.wasm)        │  │
│  │  ┌─────────────────────┐  │      │  ┌──────────────────────────┐  │  │
│  │  │ Chunk 1 (Vendors)   │  │◄────►│  │ Fast Crypto / Core Hash  │  │  │
│  │  ├─────────────────────┤  │      │  └──────────────────────────┘  │  │
│  │  │ Chunk 2 (App Logic) │  │                                       │  │
│  │  ├─────────────────────┤  │      ┌────────────────────────────────┐  │
│  │  │ Chunk 3 (Crypto/API)│  │◄────►│         Web Worker             │  │
│  │  └─────────────────────┘  │      │   Background Computation       │  │
│  └─────────────┬─────────────┘      └────────────────────────────────┘  │
│                │                                                         │
│                ▼                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Interceptors (Axios / Fetch / XHR / WebSocket)                     │  │
│  │ -> Attach Headers: X-Sign, X-Timestamp, Authorization, Nonce      │  │
│  │ -> Encrypt Payload: AES-GCM / RSA                                 │  │
│  └─────────────────────────────────┬─────────────────────────────────┘  │
└────────────────────────────────────┼────────────────────────────────────┘
                                     │ HTTPS / WSS
                                     ▼
                        ┌────────────────────────┐
                        │   WAF / Edge Gateway   │
                        │ (Cloudflare, Akamai)   │
                        └────────────┬───────────┘
                                     │
                                     ▼
                        ┌────────────────────────┐
                        │    Origin API Server   │
                        └────────────────────────┘
```

### 1. Webpack Runtime Anatomy

Webpack membungkus setiap file source code ke dalam fungsi module:
```javascript
// Struktur Webpack 5 Chunk
(self["webpackChunkmy_app"] = self["webpackChunkmy_app"] || []).push([
  ["chunk_dashboard"], // Chunk ID
  {
    "./src/api/auth.ts": function(module, exports, __webpack_require__) {
      // Kode logika modul di sini...
      exports.login = function(username, password) { ... };
    },
    "./src/utils/crypto.ts": function(module, exports, __webpack_require__) {
      const CryptoJS = __webpack_require__("./node_modules/crypto-js/index.js");
      exports.sign = function(data) { ... };
    }
  }
]);
```

**Mekanisme Hijacking Webpack di Console Browser:**
Anda bisa memanggil fungsi apapun di dalam aplikasi secara langsung dari console DevTools jika Anda mendapatkan referensi ke runtime Webpack:
```javascript
// Ekstrak instance require Webpack
let webpackRequire;
if (window.webpackChunkmy_app) {
  window.webpackChunkmy_app.push([
    ["__hack_chunk__"],
    {},
    function(req) { webpackRequire = req; }
  ]);
}
// Sekarang Anda bisa memanggil modul apapun secara bebas!
const authModule = webpackRequire("./src/api/auth.ts");
console.log("Auth Module Export:", authModule);
```

### 2. Vite & Rollup (Modern ESM)

Vite menggunakan native ES Modules (`import`/`export`) saat development dan Rollup saat production build:
- Tidak ada array global `webpackChunk`. Kode dipecah menjadi file seperti `assets/index-D3x_F9.js` dan `assets/vendor-C1a_8b.js`.
- Modul dihubungkan menggunakan pernyataan native `import { e as encrypt } from "./vendor-C1a_8b.js"`.
- Setiap chunk mengekspor fungsi dengan nama singkatan (misalnya `export { a as signRequest, b as getAuthToken }`).

### 3. Framework Server-Side Rendering (Next.js, Nuxt)

Pada aplikasi Next.js:
- Data pre-render awal disematkan di dalam tag HTML: `<script id="__NEXT_DATA__" type="application/json">`.
- Tag ini memuat seluruh prop halaman, sesi user, konfigurasi API internal, dan ID chunk dinamis.
- Selalu ekstrak isi `__NEXT_DATA__` terlebih dahulu menggunakan selector `JSON.parse(document.getElementById('__NEXT_DATA__').textContent)`.

---

## ALUR KERJA INVESTIGASI LENGKAP (WORKFLOW)

```
[Target URL / SPA]
       │
       ▼
[FASE 1: Recon & Source Discovery]
 ├─ Jalankan `sourcemap_extractor.py` untuk cek .js.map (R1)
 ├─ Inspeksi HTML untuk script `__NEXT_DATA__`, config global (window.__CONFIG__)
 └─ Unduh semua bundle JS utama (app.js, vendor.js, chunks)
       │
       ▼
[FASE 2: Unpacking & Modularisasi]
 ├─ Jalankan `webpack_unpacker.py` untuk memecah bundle menjadi modul terpisah
 ├─ Filter modul sensitif (auth, crypto, signature, api_client)
 └─ Jalankan `js_deobfuscator.py` untuk membersihkan kode terobfuskasi
       │
       ▼
[FASE 3: Dynamic Runtime Hooking (Bypass Anti-Analysis)]
 ├─ Generate Userscript via `devtools_hook_generator.py --mode all`
 ├─ Pasang di Tampermonkey (@run-at document-start) (R2)
 ├─ Buka DevTools: konfirmasi anti-debug netral, traffic XHR/Fetch tercatat
 └─ Dapatkan stack trace pemanggil fungsi penandatangan API
       │
       ▼
[FASE 4: Reverse Engineering Algoritma Signature]
 ├─ Buka file modul pemanggil di VS Code / editor
 ├─ Analisis alur input: parameter -> canonical string -> secret key -> hash function
 ├─ Identifikasi algoritma (MD5, HMAC-SHA256, AES-CBC, SM3) via `web_api_tracer.py`
 └─ Dapatkan secret key / salt dari memory runtime atau konstanta kode
       │
       ▼
[FASE 5: Replay & Automasi]
 ├─ Tulis skrip Python standalone untuk mereproduksi kalkulasi signature
 ├─ Replay request HTTP menggunakan `requests` atau `curl_cffi`
 └─ Validasi response: 200 OK dengan payload data lengkap
```

---

## TEKNIK REKONSTRUKSI KODE SUMBER (SOURCE RECOVERY)

### 1. Ekstraksi Source Map v3

File `.js.map` adalah file JSON standar dengan spesifikasi Source Map v3:
```json
{
  "version": 3,
  "file": "app.min.js",
  "sources": [
    "src/index.ts",
    "src/services/api.ts",
    "src/security/crypto.ts"
  ],
  "sourcesContent": [
    "// Source asli src/index.ts ...",
    "// Source asli src/services/api.ts ...",
    "// Source asli src/security/crypto.ts ..."
  ],
  "mappings": "AAAA,SAASA..."
}
```

Ketika `sourcesContent` ada di dalam file `.map`, seluruh source code asli tersimpan utuh.
Tool `scripts/sourcemap_extractor.py` membaca `sources` dan `sourcesContent`, lalu menulis ulang struktur direktori dan file persis seperti di laptop developer aslinya!

**Cara Penggunaan:**
```bash
# Scan halaman web otomatis (mencari komentar //# sourceMappingURL=...)
python scripts/sourcemap_extractor.py --url "https://target-app.com" --out-dir ./extracted_project

# Ekstrak dari URL bundle JS spesifik
python scripts/sourcemap_extractor.py --js-url "https://target-app.com/static/js/main.d4e1a2.js" --out-dir ./extracted_project

# Ekstrak dari file .map lokal yang sudah didownload
python scripts/sourcemap_extractor.py --file bundle.js.map --out-dir ./extracted_project
```

### 2. Webpack Chunk Disassembly

Jika Source Map tidak tersedia di server, langkah berikutnya adalah membedah Webpack chunk menggunakan `scripts/webpack_unpacker.py`.

Tool ini melakukan:
1. Pemotongan sintaks `(self.webpackChunk = ...).push([ ... ])` pada tingkat AST/tanda kurung.
2. Ekstraksi setiap modul ke dalam file `.js` terpisah.
3. Membaca komentar path Webpack (misal `/*! ./src/api/request.ts */`) untuk mengembalikan path file aslinya.
4. Memberikan tag otomatis pada modul yang mengandung keyword sensitif:
   - `[auth]`: login, token, jwt, bearer
   - `[crypto]`: aes, rsa, hmac, sha256, md5, cipher
   - `[signature]`: sign, x-sign, nonce, canonical
   - `[api_client]`: axios, baseURL, interceptors

**Cara Penggunaan:**
```bash
# Unpack semua modul dari bundle ke direktori terorganisir
python scripts/webpack_unpacker.py --file main.bundle.js --out-dir ./modules

# Hanya ekstrak modul-modul sensitif (auth, crypto, signature)
python scripts/webpack_unpacker.py --file main.bundle.js --out-dir ./modules --only-sensitive

# Output katalog modul dalam format JSON untuk integrasi script
python scripts/webpack_unpacker.py --file main.bundle.js --json
```

---

## DEOBFUSCATION & AST UNRAVELLING

Banyak situs menerapkan obfuscator JavaScript (misalnya `javascript-obfuscator`). Berikut pola-pola umum dan cara mengatasinya:

### 1. Pola String Array Obfuscation

Obfuscator menyembunyikan string sensitif (seperti URL endpoint, nama header, secret key) ke dalam array terpisah:
```javascript
// 1. Deklarasi array string
var _0xa12b = ['X-Sign', 'POST', '/api/v1/auth', 'CryptoJS'];

// 2. Fungsi rotasi array (shift IIFE)
(function(_0x2d3a, _0x1a8f) {
  var _0x4b = function(_0x5c) {
    while (--_0x5c) { _0x2d3a['push'](_0x2d3a['shift']()); }
  };
  _0x4b(++_0x1a8f);
})(_0xa12b, 0x1f4);

// 3. Fungsi dekriptor string
var _0x5f1c = function(_0x1, _0x2) {
  _0x1 = _0x1 - 0x0;
  return _0xa12b[_0x1];
};

// 4. Pemanggilan di dalam kode bisnis
var url = _0x5f1c('0x2'); // -> Mengembalikan '/api/v1/auth'
```

**Cara Deobfuscation:**
Gunakan `scripts/js_deobfuscator.py` yang mendeteksi pola array & escape hex/unicode, lalu mengembalikannya menjadi string literal:
```bash
python scripts/js_deobfuscator.py --file obfuscated.js --out clean.js
```

### 2. Pola Control Flow Flattening

Mengubah urutan eksekusi sekuensial menjadi state machine berbasis `while-switch`:
```javascript
// Kode terobfuskasi:
var _0xstate = '3|1|2|4|0'['split']('|'), _0xidx = 0;
while (true) {
  switch (_0xstate[_0xidx++]) {
    case '0': return result;
    case '1': var payload = JSON.stringify(data); continue;
    case '2': var signature = md5(payload + secret); continue;
    case '3': var secret = 'k3y_123'; continue;
    case '4': var result = send(payload, signature); continue;
  }
  break;
}

// Rekonstruksi sekuensial asli:
var secret = 'k3y_123';
var payload = JSON.stringify(data);
var signature = md5(payload + secret);
var result = send(payload, signature);
return result;
```

---

## NETRALISASI ANTI-DEBUGGING & PROTEKSI DEVTOOLS

### Ragam Teknik Anti-Debugging & Cara Melumpuhkannya

| Jenis Proteksi | Mekanisme Kerja | Dampak di DevTools | Solusi Bypass |
|---|---|---|---|
| **Infinite Debugger Loop** | `setInterval(() => { eval("debugger;"); }, 100)` | Browser membeku setiap 100ms di baris debugger | Hook `window.eval` dan `Function.prototype` untuk strip string `debugger` |
| **Function Constructor Trap** | `Function("debugger")()` dipanggil rekursif | DevTools terjebak di `<anonymous>` VM script | Wrap `window.Function` menggunakan ES6 `Proxy` |
| **Timing Check** | Mengukur selisih `performance.now()` sebelum & sesudah `debugger;` | Jika delta > 100ms, user dianggap membuka DevTools -> redirect ke 403 | Hook `Date.now` / `performance.now` untuk mengunci delta |
| **Console Poisoning** | `Object.defineProperty(console, 'log', { get: ... })` | Mendeteksi saat DevTools membaca property console | Neutralize getter trapping via proxy descriptor |
| **Window Delta Sniffing** | `window.outerWidth - window.innerWidth > 160` | DevTools dock mendeteksi pengurangan viewport | Override `outerWidth` agar selalu mengembalikan `innerWidth` |

### Solusi Cepat: Generator Hook Otomatis

Jalankan `scripts/devtools_hook_generator.py`:
```bash
# Buat Userscript Tampermonkey yang mematikan seluruh anti-debug & timing checks
python scripts/devtools_hook_generator.py --type userscript --mode anti-debug --domain target.com --out bypass_debug.user.js

# Buat snippet konsol sekali pakai untuk di-paste langsung ke DevTools
python scripts/devtools_hook_generator.py --type snippet --mode anti-debug
```

Pasang Userscript di extension browser (Tampermonkey atau Violentmonkey). Pastikan metadata `@run-at document-start` aktif agar skrip berjalan sebelum JavaScript halaman dieksekusi.

---

## REVERSE ENGINEERING API SIGNATURE & ENKRIPSI PAYLOAD

### 1. Anatomi Request Signing

Situs web modern umumnya memverifikasi integritas request API menggunakan header seperti:
```http
POST /api/v2/order/create HTTP/1.1
Host: api.target.com
Content-Type: application/json
X-App-Id: web_client_v2
X-Timestamp: 1741165200
X-Nonce: 4f9a2b8e-6d1c-4e8a
X-Sign: d41d8cd98f00b204e9800998ecf8427e
```

**Rumus kalkulasi signature yang umum ditemukan:**
$$\text{Signature} = \text{Hash}(\text{Path} + \text{SortedQueryString} + \text{BodyString} + \text{Timestamp} + \text{Nonce} + \text{SecretKey})$$

### 2. Metodologi Pelacakan Signature Langkah-demi-Langkah

1. **Jalankan API Snooper:**
   Gunakan hook fetch/XHR yang mencatat Call Stack:
   ```bash
   python scripts/devtools_hook_generator.py --type snippet --mode fetch-xhr
   ```
   Paste ke console DevTools sebelum mengklik tombol/aksi pada halaman.

2. **Trigger Aksi di Halaman:**
   Klik tombol (misalnya "Checkout", "Search", atau "Login").
   Console akan langsung mencetak grup pesan log berwarna:
   ```
   [FETCH] POST /api/v2/order/create
   Headers: { X-Sign: "...", X-Timestamp: 1741165200 }
   Called from:
       at buildHeaders (request.ts:42:15)
       at apiClient.post (client.ts:88:20)
       at handleCheckout (checkout.vue:120:5)
   ```

3. **Lompat ke Fungsi Pembuat Header:**
   Klik link `request.ts:42:15` di console DevTools. Browser akan membuka tab Sources langsung di baris kode pembuat header `X-Sign`!

4. **Pasang Breakpoint:**
   Pasang breakpoint di awal fungsi `buildHeaders`. Lakukan aksi sekali lagi.
   Saat browser berhenti di breakpoint:
   - Evaluasi nilai variabel parameter, timestamp, dan secret key di tab **Scope Variables**.
   - Periksa objek hashing (misal `CryptoJS.HmacSHA256` atau `window.crypto.subtle`).

5. **Static Pattern Scanning:**
   Gunakan `scripts/web_api_tracer.py` pada file bundle terkait untuk memverifikasi seluruh variasi algoritma kriptografi yang ada:
   ```bash
   python scripts/web_api_tracer.py --file bundle.js --query "X-Sign"
   ```

### 3. Replay Request di Python

Setelah algoritma dan kunci diketahui, buat skrip Python standalone untuk mereproduksi request:
```python
import hashlib
import time
import uuid
import requests

API_URL = "https://api.target.com/api/v2/order/create"
SECRET_KEY = "k3y_pr0duct10n_s3cr3t"

def generate_signature(path: str, body_str: str, timestamp: int, nonce: str) -> str:
    # Contoh formula canonical signature
    raw_payload = f"{path}|{body_str}|{timestamp}|{nonce}|{SECRET_KEY}"
    return hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

def make_request(data: dict):
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())
    body_str = json.dumps(data, separators=(',', ':')) # Penting: hilangkan spasi JSON
    
    sign = generate_signature("/api/v2/order/create", body_str, timestamp, nonce)
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/133.0.0.0 Safari/537.36",
        "X-App-Id": "web_client_v2",
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Sign": sign,
    }
    
    resp = requests.post(API_URL, data=body_str, headers=headers)
    return resp.json()
```

---

## REVERSE ENGINEERING WEBASSEMBLY (WASM) & WORKER THREADS

Jika logika enkripsi atau penandatanganan tidak ditemukan pada JavaScript, periksa WebAssembly:

1. **Deteksi Pemuatan WASM:**
   Di DevTools Network tab, ketik filter `mime-type:application/wasm` atau cari file berekstensi `.wasm`.
   Atau pasang hook di console:
   ```javascript
   const origInstantiate = WebAssembly.instantiate;
   WebAssembly.instantiate = function(bufferSource, importObject) {
     console.log('[WASM] Loading WebAssembly module!', bufferSource, importObject);
     return origInstantiate.apply(this, arguments);
   };
   ```

2. **Dekomposisi ke WebAssembly Text Format (`.wat`):**
   Unduh file `.wasm`, lalu konversi ke teks yang dapat dibaca manusia menggunakan toolkit WABT (`wasm2wat`):
   ```bash
   wasm2wat core_crypto.wasm -o core_crypto.wat
   ```

3. **Analisis Ekspor & Impor:**
   Buka file `.wat`. Cari bagian `(export "sign")` atau `(export "encrypt")`.
   WASM berkomunikasi dengan JS menggunakan memory buffer (`WebAssembly.Memory`). String dan pointer dilewatkan sebagai integer offset di heap memory.

---

## ANALISIS PROTOKOL REAL-TIME (WEBSOCKET & SSE)

Banyak platform modern (fintech, dashboard crypto, chat, aplikasi streaming) bertukar data biner atau event-driven melalui WebSocket.

### 1. Hooking Protokol WebSocket

Gunakan `scripts/devtools_hook_generator.py --mode websocket` atau jalankan snippet berikut di console:
```javascript
const OrigWS = window.WebSocket;
window.WebSocket = function(url, protocols) {
  const ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
  console.log('[WS] Connected to:', url);
  
  const origSend = ws.send;
  ws.send = function(data) {
    console.log('[WS SEND]', data);
    return origSend.apply(this, arguments);
  };
  
  ws.addEventListener('message', function(e) {
    console.log('[WS RECV]', e.data);
  });
  
  return ws;
};
window.WebSocket.prototype = OrigWS.prototype;
```

### 2. Decoding Frame Protobuf & Socket.IO Biner

Gunakan `scripts/ws_inspector.py` untuk menginspeksi frame biner tanpa memerlukan file schema `.proto`:
```bash
# Decode teks Socket.IO (Engine.IO format: 42["event", {...}])
python scripts/ws_inspector.py --text '42["trade_update",{"symbol":"BTCUSDT","price":95000}]'

# Decode frame biner Protobuf dari representasi Hex
python scripts/ws_inspector.py --hex "089601120774657374696e67"

# Scaffold client replay Python websockets otomatis
python scripts/ws_inspector.py --scaffold-client --url "wss://stream.target.com/ws" --out client_ws.py
```

---

## MODIFIKASI RUNTIME & LIVE OVERRIDES

Untuk menguji perubahan kode JavaScript langsung di browser tanpa perlu akses ke server target:

### 1. Chrome / Edge DevTools Local Overrides
1. Buka DevTools (`F12`) -> tab **Sources** -> tab **Overrides** (di panel kiri).
2. Klik **Select folder for overrides** dan pilih direktori lokal di laptop Anda.
3. Berikan izin browser (*Allow*).
4. Buka tab **Network**, klik kanan pada file JS target yang ingin dimodifikasi -> pilih **Save for overrides**.
5. Edit file tersebut langsung di DevTools editor atau di VS Code (tambahkan `console.log`, bypass if-check, return nilai mock).
6. Refresh halaman (`Ctrl+R`). Browser akan melayani file lokal hasil editan Anda alih-alih mengambil dari server!

### 2. Map-Local via Proxy Server
Jika Anda menggunakan mitmproxy, Charles, Proxyman, atau script lokal `web_modifier.py`:
```bash
# Jalankan Map-Local server lokal untuk mengganti bundle JS target
python scripts/web_modifier.py serve --port 8080 --map-local "/static/js/app.js=./app.clean.js"
```

---

## KATALOG TOOLS & SKRIP HELPER

Semua skrip pembantu berada di direktori `scripts/` dan siap dieksekusi:

| Skrip | Bahasa | Deskripsi & Kegunaan Utama |
|---|---|---|
| [`sourcemap_extractor.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/sourcemap_extractor.py) | Python | Ekstraksi Source Map v3, rekonsiliasi struktur project, parsing inline base64 map |
| [`webpack_unpacker.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/webpack_unpacker.py) | Python | Bedah chunk Webpack 4/5, ekstrak modul per file, deteksi modul sensitif auth/crypto/api |
| [`js_deobfuscator.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/js_deobfuscator.py) | Python | Format minified code, unpack Dean Edwards eval, decode hex/unicode, matikan debugger loop |
| [`web_api_tracer.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/web_api_tracer.py) | Python | Static scanner pelacak generator signature, interceptor Axios/Fetch, hashing MD5/SHA/AES |
| [`devtools_hook_generator.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/devtools_hook_generator.py) | Python | Generator userscript & snippet anti-debug, crypto sniffer, fetch/XHR hook, storage observer |
| [`ws_inspector.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/ws_inspector.py) | Python | WebSocket frame inspector, Protobuf & Socket.io decoder, scaffold replay client |
| [`web_modifier.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/web_modifier.py) | Python | Map-Local proxy server & dynamic userscript generator |
| [`har_analyzer.py`](file:///c:/apk-reverse/apk/.agents/skills/web-reverse/scripts/har_analyzer.py) | Python | HAR network log analyzer & cURL exporter |

---

## TROUBLESHOOTING & SYMPTOM INDEX

| Gejala Masalah | Kemungkinan Penyebab | Tindakan Perbaikan |
|---|---|---|
| Tab browser langsung *freeze* / hang saat DevTools dibuka | Target menjalankan loop `Function("debugger")()` rekursif | Pasang Userscript anti-debug via `devtools_hook_generator.py --mode anti-debug` dengan `@run-at document-start` sebelum membuka tab |
| Console log tiba-tiba terhapus secara berkala | Target memanggil `console.clear()` di dalam timer | Jalankan hook `console.clear = function() {}` |
| Signature valid di browser, tetapi gagal (401/403) saat di-replay di Python | JSON serialization berbeda (misal ada spasi setelah koma `, ` vs `,`), atau urutan query string tidak cocok | Gunakan `json.dumps(payload, separators=(',', ':'))` di Python dan pastikan sorting query params sama |
| Request signature memerlukan `X-Timestamp`, tapi server menolak dengan `Timestamp expired` | Perbedaan waktu lokal vs server (clock skew) | Ambil timestamp dari header `Date` pada response server sebelumnya untuk menghitung delta offset waktu |
| File JS tidak memiliki Source Map dan seluruh kode berupa satu baris raksasa | Webpack / Terser production build | Gunakan `webpack_unpacker.py` untuk memotong menjadi modul individual, lalu format per modul |
| Traffic API tidak muncul di tab Network DevTools | Komunikasi menggunakan WebSocket biner atau Web Worker terpisah | Periksa tab **WS** pada Network filter, atau gunakan `ws_inspector.py` dan hook WebSocket |
| Response API berupa string biner terenkripsi (misal base64 acak) | Payload dienkripsi dengan AES atau custom cipher | Pasang `devtools_hook_generator.py --mode crypto` untuk memantau panggilan `CryptoJS.AES.decrypt` atau `crypto.subtle.decrypt` di runtime |

---

## CHECKLIST VERIFIKASI SEBELUM MENYELESAIKAN ANALISIS

- [ ] Periksa ketersediaan Source Map v3 (`.js.map`).
- [ ] Pecah bundle besar menjadi modul-modul terpisah (`webpack_unpacker.py`).
- [ ] Netralisasi mekanisme anti-debugging pada fase `document-start`.
- [ ] Tangkap aliran data request API dan stack trace pemanggil (`fetch-xhr` hook).
- [ ] Petakan formula signature, kunci rahasia (secret key), nonce, dan salt.
- [ ] Validasi replay request HTTP secara independen di luar browser menggunakan skrip Python/Node.js.
