# Browser Fingerprinting, Anti-Bot Systems, and Telemetry Reversal

> Panduan komprehensif untuk menganalisis, membongkar (*reverse engineer*), dan memvalidasi mekanisme pengumpulan telemetri peramban, *browser fingerprinting*, serta mitigasi sistem Anti-Bot komersial (Cloudflare Turnstile, DataDome, Kasada, Akamai Bot Manager, PerimeterX / HUMAN).

---

## 1. Arsitektur & Dimensi Browser Fingerprinting

Sistem anti-bot modern tidak lagi hanya mengandalkan alamat IP dan User-Agent. Mereka mengumpulkan ratusan atribut unik dari lingkungan browser untuk menghasilkan profil kriptografis perangkat (*device fingerprint*):

```
+-----------------------------------------------------------------------------------+
| 1. HARDWARE & GRAPHICS LAYER                                                      |
|    - Canvas 2D: Hash render teks dan geometri 2D via toDataURL() / getImageData()|
|    - WebGL: Unmasked Vendor & Renderer (ANGLE, NVidia, Apple M-series, Mali)       |
|    - AudioContext: Dinamika frekuensi FFT osilator dan kompresor audio            |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 2. RUNTIME & AUTOMATION ATTRIBUTES                                                |
|    - Navigator: webdriver (true/false), languages, hardwareConcurrency, memory    |
|    - Automation Leaks: window.chrome, cdc_adoQpoasnfa76pfcZLmcfl, __nightmare    |
|    - Permissions API: status geolocation, notifications, state consistency       |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 3. TRANSPORT & NETWORK LAYER                                                      |
|    - JA3 / JA4: TLS Client Hello cipher suites, extensions, elliptic curves      |
|    - HTTP/2: SETTINGS frames, WINDOW_UPDATE, header priority and pseudokey order |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 4. BEHAVIORAL & SENSOR TELEMETRY                                                  |
|    - Mouse Trajectory: Titik koordinat, kurva Bezier, akselerasi, jitter        |
|    - Keystroke Dynamics: Keydown-keyup flight times, inter-key delays             |
|    - Touch / Orientation: Touch radius, force, accelerometer, devicemotion       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Bedah Vektor Fingerprinting Spesifik

### A. Canvas 2D Fingerprinting
* **Mekanisme:** Skrip menggambar elemen tersembunyi dengan font, warna, dan operasi komposit spesifik:
  ```javascript
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = "14px 'Arial'";
  ctx.fillStyle = '#f60';
  ctx.fillRect(125, 1, 62, 20);
  ctx.fillStyle = '#069';
  ctx.fillText("Cwm fjordbank glyphs vext quiz", 2, 15);
  const dataURI = canvas.toDataURL(); // Hash SHA-256 / MD5 dari dataURI
  ```
* **Titik Variasi:** Hasil rasterisasi berbeda antar OS dan kartu grafis karena perbedaan antialiasing, font smoothing, dan rendering engine (Skia vs DirectWrite vs CoreText).

### B. WebGL Renderer & Parametric Sniffing
* **Mekanisme:** Mengekstrak informasi GPU asli di balik lapisan virtualisasi browser:
  ```javascript
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
  const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
  const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
  ```
* **Karakteristik Bot/Emulator:** Nilai seperti `Google SwiftShader`, `Mesa OffScreen`, atau `llvmpipe` mengindikasikan headless browser atau render perangkat lunak (*software rendering*).

### C. AudioContext Fingerprinting
* **Mekanisme:** Membuat audio buffer sintetis dan mengalirkan sinyal melalui `DynamicsCompressorNode`:
  ```javascript
  const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const oscillator = audioCtx.createOscillator();
  const compressor = audioCtx.createDynamicsCompressor();
  // Analisis array buffer Float32Array setelah kompresi audio
  ```
* **Titik Variasi:** Perbedaan arsitektur DSP, floating point rounding, dan driver sound card menghasilkan hash numerik yang unik per perangkat keras.

---

## 3. Fingerprinting Jaringan (JA3 / JA4 & HTTP/2)

Seringkali skrip browser berhasil lolos dari audit JavaScript, namun request tetap diblokir di layer WAF (Cloudflare / Akamai). Penyebab utamanya adalah **TLS & Network Fingerprint**:

### Format JA3 Fingerprint:
```
SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
```
* Library standar Python `requests` menggunakan OpenSSL default Python, menghasilkan JA3 yang berbeda drastis dari Google Chrome resmi.
* **Solusi Operasional:** Gunakan pustaka dengan fitur impersonasi TLS seperti `curl_cffi` dengan parameter `impersonate="chrome120"` atau `tls-client`.

### Karakteristik HTTP/2 Fingerprint:
* **Frame SETTINGS:** Urutan parameter `HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`.
* **Pseudokey Ordering:** Urutan header pseudo HTTP/2:
  * Chrome: `:method`, `:authority`, `:scheme`, `:path`
  * Firefox: `:method`, `:path`, `:authority`, `:scheme`

---

## 4. Reverse Engineering Skrip Telemetri Anti-Bot

Skrip pengumpul telemetri (misal `dd.js` milik DataDome, `ips.js` milik Kasada, atau sensor script PerimeterX `px.js`) biasanya mengalami obfuskasi berat:

### Alur Rekonstruksi Collector:
1. **Identifikasi Titik Masuk (Entrypoint):**
   * Gunakan XHR Breakpoint pada endpoint posting telemetri (misal `/api/v1/event`, `/telemetry/collect`).
2. **Tracer Ekstraksi Properti:**
   * Pasang Proxy trap pada objek global untuk mencatat apa saja yang dibaca:
     ```javascript
     function monitorAccess(obj, name) {
       return new Proxy(obj, {
         get(target, prop) {
           console.log(`[TELEMETRY READ] ${name}.${String(prop)}`);
           return Reflect.get(target, prop);
         }
       });
     }
     window.navigator = monitorAccess(window.navigator, 'navigator');
     ```
3. **Penyandian & Enkripsi Payload:**
   * Kebanyakan collector memadatkan ratusan boolean/float ke dalam format bit-packing biner atau Base64 terkompresi (LZW / Deflate kustom).
   * Cari fungsi kompresi sebelum `fetch()` dipanggil untuk melihat pemetaan string key ke ID numerik.

---

## 5. Hooking & Netralisasi Runtime

Untuk menguji bagaimana aplikasi bereaksi ketika atribut browser disesuaikan atau dimonitor, gunakan skrip injeksi Tampermonkey pada `@run-at document-start`:

```javascript
// ==UserScript==
// @name         Browser Anti-Fingerprint & Telemetry Monitor
// @namespace    http://tampermonkey.net/
// @version      1.0
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
  'use strict';

  // 1. Masking navigator.webdriver
  Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
  });

  // 2. Pertahankan keaslian Function.prototype.toString
  const originalToString = Function.prototype.toString;
  const hookedFns = new WeakSet();

  function markHooked(fn) {
    hookedFns.add(fn);
    return fn;
  }

  Function.prototype.toString = function() {
    if (hookedFns.has(this)) {
      return "function () { [native code] }";
    }
    return originalToString.apply(this, arguments);
  };
  markHooked(Function.prototype.toString);

  // 3. Monitor pembacaan Canvas
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = markHooked(function(...args) {
    console.warn('[FINGERPRINT ALERT] Canvas toDataURL() dipanggil');
    return origToDataURL.apply(this, args);
  });

  // 4. Spoof WebGL Unmasked Info (jika diperlukan)
  const origGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = markHooked(function(param) {
    // 0x9245 = UNMASKED_VENDOR_WEBGL, 0x9246 = UNMASKED_RENDERER_WEBGL
    if (param === 0x9245) return 'Google Inc. (Apple)';
    if (param === 0x9246) return 'ANGLE (Apple, Apple M2 Pro, OpenGL 4.1)';
    return origGetParameter.apply(this, arguments);
  });

  console.log('[*] Anti-Fingerprint runtime protection terpasang.');
})();
```

---

## 6. Checklist Audit & Replay Telemetri

- [ ] Lacak apakah request mengirimkan token telemetri (misal cookie `datadome`, header `x-kpsdk-ct`, atau token `cf-turnstile-response`).
- [ ] Validasi apakah token tersebut terikat ke sesi IP tertentu (*IP-bound*).
- [ ] Analisis apakah payload sensor mencakup interaksi kursor mouse nyata atau hanya status hardware.
- [ ] Pastikan script replay (Python/Node.js) menggunakan cipher TLS dan urutan header HTTP/2 yang selaras dengan browser asli.
