<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <img src="assets/banner-light.svg" alt="apk-reverse" width="100%">
  </picture>
</p>

<p align="center">
  <b>Bahasa Indonesia</b> · <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="https://github.com/newliver666/apk-reverse/stargazers"><img src="https://img.shields.io/github/stars/newliver666/apk-reverse?style=flat-square&label=stars&color=49454F" alt="stars"></a>
  <a href="https://github.com/newliver666/apk-reverse/network/members"><img src="https://img.shields.io/github/forks/newliver666/apk-reverse?style=flat-square&label=forks&color=49454F" alt="forks"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/newliver666/apk-reverse?style=flat-square&color=49454F" alt="license"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-49454F?style=flat-square&logo=python&logoColor=white" alt="python">
  <img src="https://img.shields.io/badge/platform-android-49454F?style=flat-square&logo=android&logoColor=white" alt="android">
  <a href="https://github.com/newliver666/apk-reverse/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/newliver666/apk-reverse/ci.yml?style=flat-square&label=ci&color=49454F" alt="ci"></a>
</p>

<p align="center">
  <a href="#-mulai-cepat">Mulai Cepat</a> · <a href="#-fitur-lengkap">Fitur</a> · <a href="#-8-agent-skills">Skills (8)</a> · <a href="#-95-script-otomasi">Script (95+)</a> · <a href="#-80-dokumen-referensi-teknis">Referensi (80+)</a> · <a href="#-workflow-4-gate">Workflow</a> · <a href="#-perintah-cli-lengkap">CLI</a> · <a href="#-prasyarat">Prasyarat</a> · <a href="#%EF%B8%8F-disclaimer">Disclaimer</a>
</p>

---

# apk-reverse & Security Suite: Android Reverse Engineering, Web Security Audit & Cloudflare Bypass Toolkit

> 🛠️ **Dimodifikasi & Dikembangkan oleh ALDY** — Framework All-in-One: Reverse Engineering Android APK (DEX & Native), Bypass Cloudflare WAF & Turnstile, Audit Keamanan Web Standar OWASP Top 10, serta Analisis Web Client-Side (SPA/Webpack/Vite).

Sebuah ekosistem **8 Agent Skills** terpadu untuk reverse engineering aplikasi Android & Web, debloating, pemusnahan iklan, patching DEX bedah, repacking, bypass bot mitigasi Cloudflare tingkat lanjut, serta audit postur pertahanan keamanan web tingkat enterprise.

Ini adalah **kumpulan skills**, bukan sekadar tutorial — dirancang untuk dimuat secara modular oleh agen AI (**Google Antigravity IDE, Claude Code, Cursor, Codex**, atau harness AI lainnya) maupun dieksekusi langsung via CLI / `npx`. Terstruktur dengan prinsip **progressive disclosure**: manual `SKILL.md` berorientasi keputusan, 80+ referensi teknis yang dimuat on-demand, dan 95+ skrip terparameterisasi siap pakai.

---

## ⚡ Mulai Cepat

### A. Android APK Reverse Engineering
```bash
# 1. Periksa kesehatan tools dan environment
python apk_cli.py doctor

# 2. Lakukan reconnaissance pada file APK target
python apk_cli.py recon --apk target.apk

# 3. Generate laporan analisis interaktif (HTML dark-mode/JSON)
python apk_cli.py report --apk target.apk --format html --out report.html
```

### B. Web Security Audit & Vulnerability Scanning
```bash
# 1. Audit HTTP Security Headers & Cookie Flags URL Live (Skor Grade A+ s/d F)
python skills/web-security-audit/scripts/security_headers_audit.py --url https://target-web.com

# 2. Pindai kebocoran kunci API & string entropi tinggi (Shannon Entropy) pada codebase
python skills/web-security-audit/scripts/secret_scanner.py --path ./my-web-project

# 3. Audit form tanpa proteksi CSRF (@csrf) dan aksi state-change GET berisiko
python skills/web-security-audit/scripts/csrf_audit.py --url https://target-web.com

# 4. Uji kebijakan CORS terhadap arbitrary origin reflection & credential leaks
python skills/web-security-audit/scripts/cors_audit.py --url https://target-web.com/api/user
```

### C. Cloudflare & WAF Bypass Diagnostics
```bash
# 1. Deteksi lapisan pertahanan Cloudflare (Turnstile, IUAM, Bot Fight Mode)
python skills/cf-bypass/scripts/cf_detector.py --url https://protected-site.com

# 2. Pencarian IP server asal (Direct-to-Origin) untuk bypass Cloudflare WAF total
python skills/cf-bypass/scripts/cf_origin_finder.py --domain protected-site.com

# 3. Validasi TLS Fingerprint JA3/JA4 terhadap Cloudflare Bot Management
python skills/cf-bypass/scripts/cf_tls_check.py --url https://protected-site.com
```

---

## 🛠️ Instalasi & Penggunaan

### 1. Sebagai AI Agent Skill (Antigravity IDE, Claude Code, Cursor, Copilot)
Toolkit ini dirancang modular mengikuti standar Agent Skills resmi:
```bash
npx skills add ALDY711/apk-reverse-modifikasi              # Install semua 8 skills ke workspace AI agent
npx skills add ALDY711/apk-reverse-modifikasi --list       # Lihat daftar 8 skills yang tersedia
npx skills add ALDY711/apk-reverse-modifikasi --skill web-security-audit -y  # Install satu skill spesifik
npx skills use ALDY711/apk-reverse-modifikasi@cf-bypass    # Jalankan on-demand tanpa install
```

### 2. Sebagai CLI Tool via npx / npm
Jalankan 88+ skrip analisis langsung dari terminal menggunakan Node runner:
```bash
# Jalankan langsung tanpa instalasi:
npx @aldy11/apk-reverse doctor                              # Cek kesehatan tools & environment
npx @aldy11/apk-reverse recon --apk target.apk              # Lakukan reconnaissance APK
npx @aldy11/apk-reverse --skills                            # Tampilkan 8 AI Agent Skills bawaan

# Atau pasang secara global di sistem:
npm install -g @aldy11/apk-reverse
apk-reverse doctor
```

### 3. Manual (Python)
```bash
git clone https://github.com/ALDY711/apk-reverse-modifikasi.git
cd apk-reverse-modifikasi
pip install -r requirements.txt
python setup.py
```

### 4. Di Google Antigravity IDE
```bash
# Sebagai workspace skill (disarankan):
Salin folder skills/ ke .agents/skills/ di direktori proyek Anda.

# Sebagai global skill:
Salin folder skills/ ke ~/.gemini/config/skills/
```

---

## ✨ Fitur Lengkap

### 🔍 Reconnaissance & Klasifikasi
- **Identifikasi otomatis** packer (Qihoo 360, Bangcle, Ijiami, dll), SDK, dan lokasi kode
- **Pemeriksaan tamper check** dan anti-analysis detection
- **Ekstraksi string** dari DEX tanpa decompiler — URL, endpoint API, SDK markers
- **Diff APK** — bandingkan dua build berdasarkan content hash
- **Identifikasi arsitektur** — ABI dan library mana yang *benar-benar* dieksekusi

### 🔧 Patching (DEX & Native)
- **Byte-level patching** — edit DEX dengan panjang sama (equal-length), lebih aman dari rebuild
- **String patching** — ganti string di DEX dengan guard ordering `string_ids`
- **Method rewriting** — rewrite method via dexlib2 untuk perubahan yang butuh instruksi baru
- **Smali patching** — penggantian method-body di smali tree
- **Native .so patching** — same-length in-place rewrite konstanta string di shared library
- **Pencarian instruksi** — cari instruksi berdasarkan semantik decoded → offset tepat
- **Verifier check** — pastikan patch tidak melanggar aturan verifier (move-result adjacency)
- **Patch audit** — buktikan patch *landed* dan *legal*

### 📦 Repack & Sign
- **Rebuild APK** — strip hanya signature, pertahankan `META-INF/services/`
- **Zipalign** — 4-byte alignment, `resources.arsc` STORED+aligned
- **Signing** — APK Signature Scheme V1, V2, V3 via `apksigner`
- **Split APK** — handle App Bundle / split APK: inventaris, sign setiap member, atau merge
- **Verifikasi** — cek signature sebelum deploy

### 🛡️ Keamanan & Scanning
- **Leak scanner** — scan identitas target (bundle ID, serial, PAT, API key) sebelum publishing
- **TLS/certificate check** — strict certificate verification per host
- **Signature probe** — temukan `signatures[0].toCharsString()` value (offline atau dari device)
- **Desensitization** — aturan apa yang harus disensor dan apa yang harus tetap (tools, CVE, library)

### 🔬 Analisis Dinamis (Frida)
- **Four-layer runtime probe** — app net layer → OkHttp → java.net → exceptions
- **Spawn-patch-detach** — spawn di bawah Frida, detach, lalu launch dan capture
- **Anti-detection probe** — observer-only (tanpa patch): path/loader/thread/kill hooks
- **Frida RPC** — panggil fungsi live alih-alih reverse
- **Stalker tracing** — instruction-level tracing dengan Frida Stalker
- **Hook generator** — generate bypass script untuk SSL pinning dan root detection
- **Crypto monitor** — pantau AES/RSA/HMAC key secara real-time
- **JNI hook scaffold** — intersepsi parameter ke shared library `.so`

### 📱 Device & Environment
- **Preflight check** — cek device, root, ABI/translation, clock skew, proxy/forward
- **Cold-start capture** — screenshot burst + logcat + timing
- **Install & test** — install + launch health check dengan logcat signal scan
- **Screenshot burst** — bounded burst screenshot + control-tree capture
- **USB network proxy** — berikan network ke device offline via USB

### 🧩 Advanced / Hardened Target
- **Packer handling** — identifikasi, unpack, memory dump → patched installable APK
- **VMP differential** — known-plaintext differential untuk Dex VMP, derive private opcode table
- **Java2C probe** — bedakan Java2C vs extraction shell vs VMP vs JNI sinking
- **DEX dump validation** — dedupe, validasi, rank directory dumped DEX
- **Memory DEX scan** — cari embedded DEX di memory capture
- **OLLVM deobfuscation** — trace-to-CFG route via Stalker/QBDI
- **Kernel-level** — KernelSU/APatch syscall-masking scaffold
- **LSPosed module** — generate minimal LSPosed/Xposed module ketika repack ditolak
- **Emulation & RPC** — Unidbg/Unicorn emulation atau service-ify fungsi live via Frida RPC
- **Protocol reverse** — protobuf tanpa schema, gRPC, QUIC/HTTP3
- **Native crash analysis** — lokasi native death: signal, fault address, registers, frames

### 🌐 Web Reverse Engineering
- **Source Map extraction** — ekstrak file sumber asli dari JS bundle via `.js.map`
- **AST deobfuscation** — unravelling obfuscator.io, constant folding, dead-code elimination
- **Webpack & Vite unpacking** — dump chunk bundle menjadi struktur direktori project asli
- **API tracer** — trace Axios/Fetch interceptor, cryptographic signing, API endpoints
- **Anti-debugging neutralization** — bypass infinite `debugger` loop, timing checks, dan console neutering
- **WebAssembly analysis** — inspeksi memori linear WASM dan export/import table hooks
- **Userscript generator** — generate Tampermonkey userscript & Map-Local proxy

### ☁️ Cloudflare & Anti-Bot Bypass
- **Turnstile challenge solver** — otomatisasi pemecahan Cloudflare Turnstile token via API & headless browser
- **Bot Fight Mode & IUAM evasion** — bypass "I'm Under Attack Mode" dan mitigasi JavaScript Challenge
- **TLS JA3/JA4 fingerprinting** — kustomisasi Client Hello cipher suites, extension ordering, dan GREASE
- **HTTP/2 frame fingerprinting** — imitasi SETTINGS frames, WINDOW_UPDATE, dan pseudo-header priority browser Chrome
- **Direct-to-Origin discovery** — identifikasi IP asli server di balik Cloudflare via DNS history, SSL certificates, dan subdomain leaks
- **Rebrowser & Ghost Cursor integration** — eliminasi deteksi CDP runtime (`Runtime.enable`, `cdc_` markers) dan pergerakan mouse kurva Bezier

### 🛡️ Web Security Audit & Hardening
- **OWASP Top 10 compliance** — pemindaian komprehensif risiko broken access control, injection, dan cryptographic failures
- **Automated HTTP security headers grading** — skoring A+ s/d F untuk CSP, HSTS, X-Frame-Options, Permissions-Policy
- **Secret scanner (Shannon Entropy)** — pemindaian kebocoran kunci API (AWS, Stripe, GitHub, Firebase) dan high-entropy secrets
- **CORS misconfiguration audit** — deteksi arbitrary origin reflection, null origin risks, dan wildcard credentials
- **CSRF & state-change audit** — deteksi form tanpa token `@csrf` dan tautan GET sensitif
- **Laravel & Nginx remediation recipes** — resep konfigurasi langsung untuk framework Laravel 10/11 dan server Nginx/Apache

### 📊 Pelaporan
- **Markdown** — laporan dengan tabel dan badge
- **HTML** — dark theme premium dengan glassmorphism
- **JSON** — untuk integrasi otomatis
- **Mode all** — ketiga format sekaligus

### 🎯 Dart/Flutter Analysis
- **Pool string recovery** — recover literal dari Dart AOT snapshot
- **Object-pool index** — build/query pool → code-site index
- **Annotated disassembly** — windowed disassembly Dart AOT code + B/BL caller index

### 🔒 Ad Removal & Debloating
- **Taksonomi iklan** — AdMob, Unity Ads, AppLovin, ironSource, Adjust, AppsFlyer
- **Manifest neutering** — nonaktifkan komponen iklan tanpa menghapus kelas Java
- **Rewarded ad stub** — generate stub smali no-op untuk fitur yang butuh reward iklan
- **Server-config analysis** — identifikasi "iklan" yang sebenarnya server-driven UI

### 🔐 HTTPS Inspection (MITM)
- **Network Security Config injection** — trust user CA certificates
- **Certificate inspection** — periksa CA kustom dan certificate pinning bawaan
- **Cleartext traffic** — aktifkan `usesCleartextTraffic` di manifest
- **Proxy troubleshooting** — panduan saat koneksi tetap gagal

---

## 📁 8 Agent Skills

Repository ini menyediakan **8 skill modular** di bawah `skills/`:

### 1. ⭐ `apk-reverse` — Skill Inti (Terbesar)

**Reverse engineering APK end-to-end**, patching DEX/smali bedah, dan analisis komprehensif.

```
skills/apk-reverse/
├── SKILL.md              ← Prosedur 4-gate + symptom index (48 KB)
├── scripts/              ← 65+ script Python/JS
├── references/           ← 46 dokumen referensi teknis
├── evidence/             ← Capability matrix + tested tool versions
└── evals/                ← Evaluation cases
```

**SKILL.md** berisi:
- **4 Override Rules (R1–R4)** — aturan yang selalu menang jika bertentangan dengan rencana
- **Symptom Index** — katalog kegagalan yang sudah pernah terjadi (sinyal STOP)
- **4 Gates (G1–G4)** — tindakan dengan kriteria lulus yang harus dilewati berurutan
- **13 Pertanyaan Klasifikasi** — menentukan bentuk target
- **Two-Strike Rule** — 2 kegagalan dengan bentuk sama = hipotesis salah
- **Definisi "Done"** — 6 item; kurang dari 6 = checkpoint, bukan selesai

### 2. 🔬 `frida-dynamic-toolkit` — Instrumentasi Dinamis

Toolkit Frida untuk bypass perlindungan keamanan dan inspeksi runtime.

| Script | Fungsi |
|--------|--------|
| `generate_bypass.py` | Generate bypass SSL pinning (OkHttp, Flutter, Cronet) & root detection |
| `crypto_monitor.py` | Monitor kunci AES/RSA/HMAC, IV, dan hashing secara real-time |
| `jni_hook_scaffold.py` | Intersepsi parameter ke shared library .so via JNI |

| Referensi | Topik |
|-----------|-------|
| `ssl-pinning-matrix.md` | Matriks teknik SSL pinning per library |
| `root-detection-matrix.md` | Matriks teknik root detection |
| `frida-performance-and-stability.md` | Panduan performa Frida |

### 3. 🧹 `apk-debloater` — Penghapusan Iklan & Telemetry

Deteksi, debloat, dan netralisir SDK iklan secara aman.

| Script | Fungsi |
|--------|--------|
| `debloat_manifest.py` | Scan & neuter komponen iklan di AndroidManifest.xml |
| `ad_stub_gen.py` | Generate stub smali no-op untuk rewarded ads |

| Referensi | Topik |
|-----------|-------|
| `ad-signature-catalogue.md` | Katalog signature SDK iklan (AdMob, Unity, AppLovin, dll) |
| `manifest-neutering.md` | Mekanisme neutering tanpa menyebabkan ClassNotFoundException |

### 4. 🔐 `apk-mitm-patcher` — Intersepsi HTTPS

Persiapkan APK untuk proxy HTTPS (Burp Suite, mitmproxy, Charles).

| Script | Fungsi |
|--------|--------|
| `mitm_patch.py` | Injeksi Network Security Config + trust user CA |
| `cert_inspect.py` | Periksa CA kustom dan certificate pinning bawaan |

| Referensi | Topik |
|-----------|-------|
| `network-security-config-deepdive.md` | Spesifikasi XML NSC |
| `proxy-troubleshooting.md` | Troubleshooting saat proxy tetap gagal |

### 5. 📦 `apk-repacker` — Repack & Sign

Kemas ulang APK yang dimodifikasi menjadi artifact installable.

| Script | Fungsi |
|--------|--------|
| `repack_pipeline.py` | Pipeline lengkap: zipalign + bersihkan META-INF + sign |
| `apk_signer.py` | Signing V1/V2/V3 + verifikasi |

| Referensi | Topik |
|-----------|-------|
| `apk-signing-schemes.md` | Perbedaan skema signing V1, V2, V3 |
| `zipalign-and-compression.md` | Aturan alignment dan kompresi |

### 6. ☁️ `cf-bypass` — Cloudflare WAF & Anti-Bot Evasion

Bypass dan otomatisasi mitigasi Cloudflare IUAM, Turnstile challenges, Bot Fight Mode, dan Enterprise WAF.

```
skills/cf-bypass/
├── SKILL.md              ← Manual arsitektur 15 bagian + aturan R1-R14 (35 KB)
├── scripts/              ← 10 script otomasi deteksi, TLS, & solver
└── references/           ← 8 dokumen teknis internal Cloudflare
```

| Script | Fungsi |
|--------|--------|
| `cf_detector.py` | Deteksi lapisan proteksi CF: IUAM, Turnstile, BFM, WAF |
| `turnstile_api_solver.py` | Solver otomatis token Cloudflare Turnstile |
| `cf_origin_finder.py` | Cari IP origin di balik CF via DNS history, certs & subdomains |
| `cf_tcp_tuner.py` | Tuning TCP stack (MSS, Window Scale, SACK) untuk menyamai OS |
| `cf_tls_check.py` | Analisis fingerprint TLS (JA3/JA4) dan cipher suites |
| `cf_session.py` | Wrapper session HTTP anti-bot (curl_cffi/cloudscraper) |
| `cf_cantarella_client.py` | Integrasi Cantarella/Rebrowser untuk bypass tingkat tinggi |
| `cf_cookie_inspector.py` | Audit cookie Cloudflare (`cf_clearance`, `__cf_bm`) |
| `cf_worker_proxy.js` | Reverse proxy edge via Cloudflare Worker |
| `cf_pipeline.js` | Pipeline eksekusi headless browser anti-deteksi |

| Referensi | Topik |
|-----------|-------|
| `cloudflare-turnstile-internals.md` | Anatomi Turnstile, telemetri cData, dan challenge flow |
| `tls-fingerprinting-and-ja4-suite.md` | Spesifikasi JA3, JA4, cipher order, ALPN, GREASE |
| `http2-and-quic-frame-fingerprinting.md` | Karakteristik frame HTTP/2 dan deteksi QUIC |
| `v8-engine-and-browser-internals.md` | Evasion deteksi V8 prototype, console, dan memory |
| `canvas-webgl-audiocontext-deep-dive.md` | Bypass sidik jari perangkat keras (Canvas/WebGL/Audio) |
| `origin-discovery-playbook.md` | Playbook komprehensif menemukan IP origin server |
| `browser-automation-evasion-matrix.md` | Matriks stealth Playwright, Puppeteer, Camoufox |
| `proxy-networks-and-ip-reputation.md` | Manajemen IP reputasi, ASN scoring, dan residential proxy |

### 7. 🌐 `web-reverse` — Web Application Reverse Engineering

Deobfuscasi client-side, ekstraksi Source Maps v3, rekonstruksi Webpack/Vite bundle, dan tracing API request signing.

```
skills/web-reverse/
├── SKILL.md              ← Manual deobfuscasi, anti-debug, & AST (34.6 KB)
├── scripts/              ← 8 script ekstraksi, deobfuscator, & hook tracer
└── references/           ← 4 dokumen arsitektur web client-side
```

| Script | Fungsi |
|--------|--------|
| `sourcemap_extractor.py` | Ekstraksi file source code asli dari file `.js.map` |
| `webpack_unpacker.py` | Unpack chunk Webpack/Vite menjadi struktur folder project |
| `js_deobfuscator.py` | Deobfuscate AST, unpack p.a.c.k.e.r, decode string array |
| `web_api_tracer.py` | Trace Fetch, Axios, WebSocket, dan kriptografi frontend |
| `devtools_hook_generator.py` | Generator skrip Tampermonkey / Console hook instan |
| `har_analyzer.py` | Analisis file HTTP Archive (HAR) untuk ekstraksi flow API |
| `ws_inspector.py` | Inspeksi dan decodes frame WebSocket real-time |
| `web_modifier.py` | Proxy interceptor Map-Local untuk live tampering |

| Referensi | Topik |
|-----------|-------|
| `ast-deobfuscation-and-unravelling.md` | Teknik manipulasi AST Babel/Esprima untuk deobfuscasi |
| `webpack-and-vite-bundle-internals.md` | Anatomi chunk loader Webpack 5 dan Rollup/Vite ESM |
| `api-signature-and-request-signing-playbook.md` | Reverse engineering tanda tangan HMAC/SHA256 request API |
| `wasm-reverse-engineering-and-memory-hooking.md` | Disassembly WebAssembly (WAT), linear memory, dan JNI-like exports |

### 8. 🛡️ `web-security-audit` — OWASP Top 10 Audit & Defensive Hardening

Audit postur pertahanan aplikasi web, verifikasi kepatuhan OWASP, pengujian keamanan header, mitigasi CORS/CSRF, serta scanning kebocoran kredensial statis.

```
skills/web-security-audit/
├── SKILL.md              ← Manual master audit defensif 15 bab (30.2 KB)
├── scripts/              ← 5 script audit header, CORS, CSRF, & secret scanner
└── references/           ← 8 dokumen pengerasan standar OWASP & framework
```

| Script | Fungsi |
|--------|--------|
| `security_headers_audit.py` | Audit live HTTP security headers (Grade A+ s/d F) + generator config |
| `cors_audit.py` | Uji pantulan arbitrary origin, null origin, & wildcard credentials |
| `csrf_audit.py` | Audit form POST tanpa token CSRF & link GET sensitif |
| `secret_scanner.py` | Pindai kebocoran kunci API & string Shannon Entropy $H(X) \ge 4.2$ |
| `static_code_audit.py` | Pindai sintaks rawan, APP_DEBUG=true, raw output `{!!`, dan fungsi eval |

| Referensi | Topik |
|-----------|-------|
| `owasp-secure-headers-guide.md` | Panduan lengkap CSP, HSTS, X-Frame-Options, Permissions-Policy |
| `cors-hardening-playbook.md` | Buku panduan konfigurasi CORS yang aman dan anti-bocor |
| `laravel-security-hardening-bible.md` | Manual pengerasan arsitektur Laravel 10 & 11 (Session, .env, Middleware) |
| `owasp-top-10-defensive-manual.md` | Analisis defensif dan mitigasi 10 risiko utama OWASP Top 10 |
| `api-security-and-jwt-hardening.md` | Pengamanan REST/GraphQL API, mitigasi serangan JWT, BOLA/IDOR |
| `secure-file-upload-architecture.md` | Arsitektur upload aman, anti-RCE, re-encoding GD, & isolasi web server |
| `content-security-policy-deep-dive.md` | CSP Level 3, cryptographic nonce, mode Report-Only |
| `database-and-orm-hardening.md` | SQLi defense, PDO parameter binding, & mitigasi Mass Assignment |

---

## 🛠️ 95+ Script Otomasi

Semua script didistribusikan ke dalam masing-masing folder `skills/<skill-name>/scripts/` dan dapat dijalankan langsung via Python/Node atau melalui runner terintegrasi.

### 🏥 Diagnostik & Environment

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `doctor.py` | 29 KB | **Jalankan pertama!** Capability report, cek runnability per-script, temukan tools off-PATH |
| `preflight.py` | 11 KB | Cek environment sebelum eksperimen: device, root, ABI, clock skew, proxy |
| `coldstart.py` | 12 KB | Cold-launch: screenshot burst + logcat + timing |
| `snap.py` | 8.9 KB | Burst screenshot + control-tree capture + stall detector |
| `install_test.py` | 4.6 KB | Install + launch health check + logcat signal scan |
| `capabilities.py` | 52 KB | Mesin capability report yang mendasari doctor.py |

### 🔍 Analisis & Reconnaissance

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `dexutil.py` | 32 KB | DEX reader dependency-free: structural walk + instruction decode + header recompute |
| `dex_strings.py` | 6.3 KB | Strings/URL/SDK markers tanpa decompiler |
| `dex_find_insn.py` | 11 KB | Cari instruksi berdasarkan semantik decoded → byte offset tepat + context |
| `find_refs.py` | 10 KB | Hitung caller sebuah method sebelum patching |
| `dex_classdiff.py` | 4.8 KB | Buktikan dex edit itu surgical (bedah, bukan penghancuran) |
| `apk_diff.py` | 5.6 KB | Entry-level diff dua build: changed/added/removed by content hash |
| `lib_map.py` | 9.3 KB | Library apa yang *benar-benar* mapped ke proses live |
| `elf_plt.py` | 15 KB | Resolve PLT stub → imported symbol (x86_64 + aarch64) |
| `sig_probe.py` | 10 KB | Temukan `signatures[0].toCharsString()` — offline atau dari device |
| `java2c_probe.py` | 44 KB | Bedakan Java2C vs extraction shell vs VMP — evidence berlabel strong/medium/weak |
| `native_crash.py` | 11 KB | Lokasi native death: signal, fault addr, registers, frames, faulting instruction |
| `blob_decode.py` | 11 KB | Decode stored value: base64/hex × rotation × deflate; re-encode untuk round trip |
| `svc_scan.py` | 21 KB | Nama syscall di balik inline `svc`, segment tempat tinggalnya |
| `dex_dump_validate.py` | 19 KB | Dedupe, validasi, rank dumped DEX — trivial-body ratio untuk deteksi extraction shell |
| `dex_mem_scan.py` | 9.9 KB | Cari embedded DEX di memory capture berdasarkan header size |
| `device_shell.py` | 13 KB | ADB shell helper yang aman |
| `jni_export_resolve.py` | 6.8 KB | Resolve JNI export symbols |

### 🔨 Patching & Modifikasi Universal

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `dex_patch_bytes.py` | 17 KB | Equal-length byte patch dari JSON spec + verifier check + header recompute |
| `dex_strpatch.py` | 5.1 KB | Byte-level string patch dengan guard `string_ids` ordering |
| `dex_check_verifier.py` | 7.2 KB | Tier-3 check: conditional branch target move-result? Bandingkan 2 build |
| `patch_smali.py` | 3.9 KB | Method-body replacement di smali tree |
| `so_constpatch.py` | **54 KB** | Same-length in-place rewrite konstanta string di .so (ARM/ARM64) |
| `smtool.py` | 3.7 KB | baksmali/smali wrapper dengan configurable classpath |
| `dexpatch/` | dir | dexlib2 method-level rewriter (untuk perubahan yang butuh instruksi baru) |
| `universal_apk_modder.py` | 14 KB | Injeksi watermark branding, custom update banner, patch package name, & anti-tamper |
| `apk_patcher_studio.py` | 10 KB | Interactive surgical patching studio: replace assets, patch DEX strings, inject NSC, neuter analytics |
| `whatsapp_mod_toolkit.py` | 13 KB | Toolkit modifikasi mendalam WhatsApp: Delta/GB themes, anti-revoke message, freeze last seen, privacy bypass |

### 📦 Repack & Sign

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `repack.py` | **65 KB** | Rebuild APK, strip signatures, align, sign, verify; juga split APK/Bundle |
| `apk_mod_repack.py` | 19 KB | Pipeline repack modifikasi |

### 🌐 Network & Protocol

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `probe_api.py` | 4.4 KB | Probe HTTP API dengan header yang tepat |
| `tls_check.py` | 13 KB | Strict certificate check per host |
| `usb_net_proxy.py` | 5.5 KB | Network over USB untuk device offline |
| `protobuf_decode_raw.py` | **54 KB** | Schema-free protobuf decode → JSON tree + byte-exact re-encode |

### 🔬 Frida / Analisis Dinamis

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `frida_probe.js` | 23 KB | Four-layer runtime probe (app net → OkHttp → java.net → exceptions) |
| `run_probe.py` | 15 KB | Inject probe, stream ke log, stay resident |
| `spawn_patch_detach.py` | 10 KB | Spawn under Frida, detach, capture — hook survive sebagai memory write |
| `hook_patch_only.js` | 3 KB | Minimal probe — neutralise satu native death site |
| `anti_detect_probe.js` | 14 KB | Observer-only: path/loader/thread/kill hooks + caller info |
| `frida_rpc_serve.py` | 17 KB | Bridge rpc.exports ke local caller dengan reconnect |
| `rpc_template.js` | 3.1 KB | Editable companion untuk frida_rpc_serve.py |
| `stalker_trace.js` | 24 KB | Instruction-level tracing: configurable targets, trigger, event stream |
| `stalker_report.py` | 10 KB | Reduce stalker log → block histograms + call sequences |
| `frida_hook_gen.py` | 11 KB | Generator script Frida (unpin, root, crypto) |

### 🌍 Web Reverse Engineering (`skills/web-reverse/scripts/`)

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `sourcemap_extractor.py` | 16 KB | Ekstrak source files dari JS bundle via Source Maps (.js.map) |
| `webpack_unpacker.py` | 14 KB | Unpack chunk bundle Webpack/Vite menjadi file source asli |
| `js_deobfuscator.py` | 12 KB | Deobfuscate JS, unpack p.a.c.k.e.r, decode hex escapes, neutralize debugger |
| `web_api_tracer.py` | 11 KB | Trace Axios/Fetch interceptor, Crypto, API endpoints |
| `devtools_hook_generator.py` | 9.8 KB | Generator console hooks & Tampermonkey userscript instan |
| `har_analyzer.py` | 10 KB | Analisis file HTTP Archive (HAR) untuk ekstrak alur API rahasia |
| `ws_inspector.py` | 8.5 KB | Inspeksi & decode traffic WebSocket interaktif |
| `web_modifier.py` | 14 KB | Generate Tampermonkey userscript & Map-Local HTTP interceptor proxy |
| `curl_to_replay.py` | 7.5 KB | Konversi cURL command menjadi Python replay script (curl_cffi/requests/httpx) |
| `telemetry_inspector.py` | 8.8 KB | Deteksi sensor fingerprinting (Canvas, WebGL, Audio) & auto-generate hooks |
| `auth_flow_tracer.py` | 11 KB | Scanner enkripsi client-side (RSA JSEncrypt, CryptoJS AES/SHA), audit JWT token, & generator replay TLS |

### ☁️ Cloudflare & Anti-Bot Bypass (`skills/cf-bypass/scripts/`)

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `cf_detector.py` | 12 KB | Deteksi proteksi CF: IUAM, Turnstile, Bot Fight Mode, Enterprise WAF |
| `turnstile_api_solver.py` | 11 KB | Solver otomatis challenge token Cloudflare Turnstile |
| `cf_origin_finder.py` | 14 KB | Cari IP server asal (Direct-to-Origin) via DNS records & certs |
| `cf_tcp_tuner.py` | 8.4 KB | Tuning parameter TCP stack (MSS, Window Size, SACK) |
| `cf_tls_check.py` | 10 KB | Analisis fingerprint TLS (JA3/JA4) dan cipher suites |
| `cf_session.py` | 9.2 KB | Session HTTP wrapper anti-bot dengan TLS impersonation |
| `cf_cantarella_client.py` | 12 KB | Klien integrasi browser Camoufox/Cantarella anti-CDP |
| `cf_cookie_inspector.py` | 7.8 KB | Validasi & monitoring cookie clearance (`cf_clearance`, `__cf_bm`) |
| `cf_worker_proxy.js` | 6.5 KB | Edge reverse proxy script via Cloudflare Worker |
| `cf_pipeline.js` | 11 KB | Automated headless browser pipeline dengan Ghost Cursor |

### 🛡️ Web Security Audit & Hardening (`skills/web-security-audit/scripts/`)

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `security_headers_audit.py` | 13 KB | Audit header keamanan HTTP live, scoring A+ s/d F, generator config |
| `cors_audit.py` | 9.7 KB | Uji pantulan origin acak, null origin, dan kredensial wildcard |
| `csrf_audit.py` | 14 KB | Audit form tanpa token @csrf, aksi GET berisiko, & SameSite cookies |
| `secret_scanner.py` | 13 KB | Pindai kebocoran kunci API & string Shannon Entropy $H(X) \ge 4.2$ |
| `static_code_audit.py` | 11 KB | Analisis statis codebase (.env, APP_DEBUG, raw output, fungsi eval) |
| `ssrf_validator.py` | 10 KB | Validasi SSRF, deteksi obfuskasi IP & cloud metadata (169.254.169.254) |
| `subdomain_takeover_audit.py` | 8.2 KB | Audit rekaman Dangling CNAME & deteksi potensi subdomain takeover |
| `sql_auth_auditor.py` | 10 KB | Audit SQLi pada form Login/Register, evaluasi hashing password (Argon2id/Bcrypt vs MD5), & prepared statements |
| `idor_bola_auditor.py` | 8.5 KB | Audit Insecure Direct Object References (IDOR/BOLA) pada backend controller, validasi tenant scoping |
| `rate_limit_audit.py` | 9.2 KB | Audit endpoint sensitif terhadap ketiadaan Rate Limiting/Throttling, generator sliding-window Redis & Nginx |

### 🎯 Dart/Flutter

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `dart_pool_strings.py` | 10 KB | Recover literal dari Dart AOT snapshot (one-byte vs UTF-16) |
| `dart_pprefs.py` | 7.8 KB | Build/query object-pool → code-site index |
| `dart_disasm.py` | 8.5 KB | Annotated windowed disassembly + B/BL caller index |

### 🛡️ Security & Scanning

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `scan_leaks.py` | 35 KB | Scan identitas target: bundle ID, serial, PAT, API key, endpoints |
| `grab_crash.py` | 3.6 KB | Recover stack dari crash-reporter SDK |
| `datastore_inject.py` | 13 KB | Encode/inject AndroidX DataStore preferences |

### 🏗️ Advanced / Module

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `lsposed_scaffold.py` | 19 KB | Generate minimal LSPosed/Xposed module project |
| `mt_mcp_probe.py` | 8.6 KB | Probe MT Manager's on-device MCP (port 8787) |
| `vmp_diff_harness.py` | **73 KB** | VMP differential: derive private opcode table, smali skeleton |
| `kernelsu_syscall_mask.py` | 38 KB | KernelSU/APatch syscall-masking scaffold |
| `rasc_build.py` | 12 KB | Build & verify rasc (Rust ASC reimplementation) |

### 📊 Reporting & Utility

| Script | Ukuran | Fungsi |
|--------|--------|--------|
| `report_generator.py` | 22 KB | Laporan analisis APK: Markdown/HTML/JSON |
| `devsh.py` | 4.6 KB | Quoting-safe ADB shell helper |
| `apk_debloater.py` | 9.3 KB | Debloater terintegrasi |
| `apk_mitm_patch.py` | 11 KB | MITM patcher terintegrasi |

## 📚 80+ Dokumen Referensi Teknis

Semua referensi berada di dalam direktori `skills/<skill-name>/references/` dan dimuat **on-demand** (hanya saat dibutuhkan).

### 🎯 Inti Reverse Engineering

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `pitfalls.md` | **63 KB** | **File paling berharga!** Katalog lengkap semua kegagalan yang pernah terjadi |
| `recon.md` | 11 KB | Identifikasi packer, SDK, lokasi kode, tamper check, unpacking |
| `toolchain.md` | 41 KB | Tool apa saja, cara invoke, version-alignment, tools off-PATH |
| `routing.md` | 35 KB | Inventaris on-demand: semua referensi + script + mirror symptom index |
| `evidence-summary.md` | 14 KB | Ringkasan capability + evidence yang bisa dibuka di installed copy |
| `verification.md` | 7.9 KB | Claim ladder; definisi "done" |

### 🔧 Patching, Modifikasi & Build

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `byte-level-patching.md` | 11 KB | Equal-length byte edit: lebih baik dari method rebuild (terukur) |
| `dex-patching.md` | 11 KB | Tabel patch-layer + teknik dexlib2 mendalam |
| `patch-audit.md` | 8.3 KB | Buktikan patch *landed* dan *legal* |
| `repack-and-sign.md` | 14 KB | Aturan repack, signing, post-install hazards |
| `split-apk.md` | 21 KB | App Bundle / split APK: pull, sign, merge |
| `universal-apk-modding-and-patching-guide.md` | 14 KB | Panduan komprehensif modifikasi APK universal, inject dialog, watermark, & packaging |
| `whatsapp-mod-architecture-and-bot-integration.md` | 15 KB | Arsitektur modifikasi WhatsApp (GB/Delta/Plus), privasi, anti-hapus, & integrasi bot |
| `license-bypass-and-feature-unlocking.md` | 13 KB | Rekayasa balik lisensi premium, Play Billing stubbing, & subscription gate bypass |
| `cryptographic-analysis-and-decryption.md` | 12 KB | Ekstraksi kunci enkripsi AES/RSA/ChaCha20, dynamic key derivation, & offline decryptor |
| `app-cloning-and-repackaging.md` | 11 KB | Arsitektur kloning aplikasi: package name renaming, Provider authority remapping |
| `deep-internals-and-smali-surgery.md` | 14 KB | Bedah Smali tingkat lanjut: register manipulation, bytecode injection, dead-code pruning |
| `troubleshooting-repack-install-failures.md` | 12 KB | Diagnosis kegagalan instalasi APK: INSTALL_PARSE_FAILED, signatures, alignment mismatch |
| `cryptographic-interception-and-key-extraction.md` | 11 KB | Intersepsi kriptografi dinamis via Frida: hooking KeyStore, Cipher.init, & SecretKeySpec |

### 🛡️ Perlindungan & Hardening

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `packers.md` | 8.9 KB | Target hardened: sinyal rejection, boundary validation |
| `code-virtualization-and-custom-linkers.md` | 11 KB | VMP, custom loader, signature killer |
| `native-tamper-and-suicide.md` | 16 KB | Cara library hardened membunuh prosesnya sendiri |
| `detection-and-anti-analysis.md` | 22 KB | Saat app melawan balik / tool tidak bisa jalan |
| `native-and-so.md` | 11 KB | .so hosts, DT_NEEDED, JNI_OnLoad, relocation |
| `advanced-unpacking.md` | 41 KB | Dump body kosong, FART-style, extraction-shell diagnosis |
| `java2c-and-jni-sinking.md` | 12 KB | Java2C vs extraction shell vs VMP — tabel pemisah |
| `vmp-differential-analysis.md` | 17 KB | Known-plaintext differential untuk real Dex VMP |
| `kernel-and-environment-hardening.md` | 23 KB | Raw `svc`, init_array, kernel-route map |
| `native-dbi-and-deobfuscation.md` | 23 KB | OLLVM, Stalker traces, trace-to-CFG |

### 🌐 Network, Server & Protocol

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `server-config-and-updates.md` | 7.9 KB | Server-driven UI yang sering salah didiagnosis sebagai "iklan" |
| `server-api.md` | 5.1 KB | Probe API app; buktikan siapa pemilik gate |
| `tls-and-cert.md` | 13 KB | Kegagalan TLS per-fitur: expired cert, dual trust chain |
| `protocol-reverse.md` | 23 KB | Protobuf tanpa schema, gRPC, QUIC/HTTP3 |

### 🔑 Akses & Keamanan

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `signature-derived-keys.md` | 7.4 KB | Sertifikat signing sebagai key material |
| `account-gates.md` | 9.5 KB | Sign-in wall, guest mode, client vs server gate |
| `membership-and-limits.md` | 5.4 KB | Server vs client authority; apa yang bisa/tidak bisa di-patch |
| `updates-and-forced-upgrade.md` | 14 KB | Menjaga patched build tetap hidup; version check neutralization |
| `third-party-builds.md` | 6.9 KB | Audit APK "cracked"/"modded" sebelum trust |
| `desensitization-and-leak-scans.md` | 18 KB | Aturan publishing: apa yang disensor, apa yang tetap |

### 📱 Device, Runtime & Framework

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `environment.md` | 16 KB | Setup device/emulator, root, ADB, log signals, recovery |
| `runtime-data.md` | 12 KB | DataStore / SharedPreferences / SQLite / protobuf |
| `dynamic-frida.md` | 27 KB | Frida setup, version pinning, four-layer probe, hook strategy |
| `framework-runtimes.md` | 7.1 KB | Flutter / React Native / Unity: layer mana yang owns UI |
| `dart-aot.md` | 23 KB | Dart AOT: version pinning, object pool, decompiler, patching |
| `on-device-tooling.md` | 10 KB | MT Manager, LSPosed Manager, Termux+Frida |
| `lsposed-and-modules.md` | 23 KB | Module LSPosed ketika repack ditolak |
| `emulation-and-rpc.md` | 22 KB | Unidbg/Unicorn emulation vs Frida RPC |

### 📐 Metodologi & Disiplin

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `long-task-discipline.md` | 22 KB | Live record, drift control, timeout calibration |
| `ad-removal.md` | 14 KB | Taksonomi iklan, wrapper mapping, callback trap |
| `web-reverse.md` | 8.6 KB | Source map, JS deobfuscation, anti-debug, userscript |
| `rasc-and-droidsaw.md` | 9.3 KB | Rust ASC indexer reimplementation |
| `coverage-and-limits.md` | 16 KB | Claim ladder diterapkan ke skill itu sendiri |
| `handoff-boundaries.md` | 5.7 KB | Di mana skill ini berakhir dan disiplin lain dimulai |
| `panduan-cepat.md` | 9.5 KB | 🇮🇩 Panduan langkah demi langkah Bahasa Indonesia |

### ☁️ Cloudflare & WAF Evasion (`skills/cf-bypass/references/`)

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `cloudflare-turnstile-internals.md` | 13 KB | Anatomi Turnstile, challenge token, cData telemetry |
| `tls-fingerprinting-and-ja4-suite.md` | 15 KB | JA3, JA4, TLS cipher suite ordering, ALPN, GREASE |
| `http2-and-quic-frame-fingerprinting.md` | 14 KB | Karakteristik frame HTTP/2, SETTINGS, window update, QUIC |
| `v8-engine-and-browser-internals.md` | 16 KB | Evasion deteksi engine V8: prototypes, console, CDP markers |
| `canvas-webgl-audiocontext-deep-dive.md` | 14 KB | Bypass sidik jari hardware (Canvas 2D, WebGL, AudioContext) |
| `origin-discovery-playbook.md` | 13 KB | Playbook menemukan IP origin di balik proteksi Cloudflare |
| `browser-automation-evasion-matrix.md` | 15 KB | Matriks stealth Playwright, Puppeteer, Camoufox, Rebrowser |
| `proxy-networks-and-ip-reputation.md` | 12 KB | Strategi IP reputasi, residential proxy, ASN scoring |

### 🌐 Web Reverse Engineering (`skills/web-reverse/references/`)

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `ast-deobfuscation-and-unravelling.md` | 14 KB | AST transform via Babel: constant folding, dead code removal |
| `webpack-and-vite-bundle-internals.md` | 13 KB | Anatomi chunk loader Webpack 5, Rollup, Vite dynamic imports |
| `api-signature-and-request-signing-playbook.md` | 12 KB | Reverse engineering request signing (HMAC, SHA256, timestamps) |
| `wasm-reverse-engineering-and-memory-hooking.md` | 15 KB | Disassembly WebAssembly (WAT), linear memory buffer, imports hook |
| `browser-fingerprinting-and-telemetry-reversal.md` | 10 KB | Analisis sensor Canvas, WebGL, AudioContext, JA3/JA4, & mitigasi |
| `client-storage-serviceworker-and-offline-sync.md` | 9.5 KB | Reverse engineering IndexedDB, LevelDB, Service Worker, & WebCrypto |
| `auth-flow-and-client-encryption-reversal.md` | 11 KB | Rekayasa balik alur login, enkripsi kata sandi client-side (JSEncrypt RSA/CryptoJS), & peniruan TLS JA3/JA4 |

### 🛡️ Web Security Audit & Hardening (`skills/web-security-audit/references/`)

| Dokumen | Ukuran | Topik |
|---------|--------|-------|
| `owasp-secure-headers-guide.md` | 5.0 KB | Panduan lengkap CSP, HSTS, X-Frame-Options, Permissions-Policy |
| `cors-hardening-playbook.md` | 3.9 KB | Mitigasi Arbitrary Origin Reflection, null origin, & credentials |
| `laravel-security-hardening-bible.md` | 11 KB | Panduan pengerasan Laravel 10/11 (.env, Session, CORS, Blade) |
| `owasp-top-10-defensive-manual.md` | 7.3 KB | Analisis defensif dan mitigasi 10 risiko utama OWASP Top 10 |
| `api-security-and-jwt-hardening.md` | 14 KB | Keamanan REST/GraphQL API, mitigasi serangan JWT, BOLA/IDOR |
| `secure-file-upload-architecture.md` | 13 KB | Arsitektur upload aman, anti-RCE, polyglot stripping, isolasi server |
| `content-security-policy-deep-dive.md` | 8.8 KB | CSP Level 3, cryptographic nonce, mode Report-Only & rollout |
| `database-and-orm-hardening.md` | 8.3 KB | SQLi defense, PDO parameter binding, & mitigasi Mass Assignment |
| `ssrf-and-cloud-metadata-defense.md` | 9.8 KB | Mitigasi SSRF, proteksi cloud metadata AWS/GCP/Azure, & DNS Rebinding |
| `subdomain-takeover-and-dns-security.md` | 8.5 KB | Audit Dangling CNAME, pencegahan Subdomain Takeover, & standar DNS |
| `sql-injection-and-auth-hardening-bible.md` | 11 KB | Panduan teknis pencegahan SQL Injection login/register, Second-Order SQLi, & standarisasi password hashing |
| `idor-and-access-control-hardening-guide.md` | 10 KB | Panduan komprehensif pengerasan kendali akses, pencegahan IDOR & BOLA pada REST API |
| `rate-limiting-and-anti-automation-bible.md` | 12 KB | Pertahanan anti-automasi, mitigasi credential stuffing, SMS toll fraud, & sliding window rate limiting |

---

## 🎯 Workflow 4-Gate

Skill ini menggunakan **sistem gate prosedural** — setiap gate harus lulus sebelum lanjut ke berikutnya.

```
┌─────────────────────────────────────────────────────────────────┐
│                     MULAI ANALISIS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Gate 1: BENTUK DELIVERABLE                                     │
│  ├─ Rebuilt APK?                                                │
│  ├─ LSPosed Module?                                             │
│  ├─ Local RPC Service?                                          │
│  └─ Analysis Report?                                            │
│                          ↓                                      │
│  Gate 2: ENVIRONMENT TRUTH                                      │
│  ├─ Device/emulator terhubung?                                  │
│  ├─ Root tersedia?                                              │
│  ├─ ABI benar?                                                  │
│  └─ Clock sync? Proxy bersih?                                   │
│                          ↓                                      │
│  Gate 3: CODE LOCATION                                          │
│  ├─ Di mana logika bisnis tinggal?                              │
│  ├─ DEX? Native .so? Dart AOT? Flutter?                         │
│  └─ Control build berhasil install + launch?                    │
│                          ↓                                      │
│  Gate 4: BASELINE & CONTROL                                     │
│  ├─ Repack TANPA patch → install → launch → tes fitur           │
│  └─ Jika gagal di sini = masalah environment, bukan patch       │
│                          ↓                                      │
│  WORKFLOW: Recon → Patch → Repack → Verify                      │
│                          ↓                                      │
│  DONE? (6 item):                                                │
│  □ Deliverable tertulis                                         │
│  □ Terinstall di device                                         │
│  □ Fitur target berfungsi                                       │
│  □ Tidak ada regresi                                            │
│  □ Leak scan bersih                                             │
│  □ Log record lengkap                                           │
│                                                                 │
│  Kurang dari 6 = CHECKPOINT, bukan selesai                      │
└─────────────────────────────────────────────────────────────────┘
```

### 4 Override Rules

| Rule | Aturan |
|------|--------|
| **R1** | Tulis deliverable sebagai kalimat yang bisa diuji |
| **R2** | Ubah satu variabel saja; selalu punya control build |
| **R3** | Jangan klaim selesai tanpa verifikasi langsung di device |
| **R4** | Identifikasi layer yang benar sebelum patch |

### Two-Strike Rule

> **Dua kegagalan dengan bentuk yang sama = hipotesis salah, bukan parameternya.**
> Varian ke-3 dari hipotesis yang sudah gagal 2 kali adalah tempat waktu mati.

### Symptom Index

Setiap baris di symptom index adalah kegagalan yang sudah pernah dibayar. Jika ada yang cocok:
**STOP** → baca file rujukan terlebih dahulu, jangan coba lagi dulu.

---

## 📋 Perintah CLI Lengkap

CLI terpadu (`apk_cli.py`) membungkus semua 65+ script ke dalam subcommand terorganisir:

### Environment & Setup

```bash
python apk_cli.py doctor                        # Cek kesehatan lingkungan
python apk_cli.py doctor --json                  # Output JSON
python apk_cli.py doctor --scripts               # Cek runnability script
python apk_cli.py doctor --capabilities          # Capability report
python apk_cli.py doctor --device                # Cek koneksi device
```

### Reconnaissance

```bash
python apk_cli.py recon --apk target.apk         # Rekon lengkap
python apk_cli.py strings target.apk             # Ekstrak string dari DEX
python apk_cli.py list                            # Daftar semua script tersedia
```

### Patching

```bash
python apk_cli.py patch dex-bytes --spec patch.json --dex classes.dex   # Byte-level patch
python apk_cli.py patch dex-string --dex classes.dex --old "str" --new "str2"  # String patch
python apk_cli.py patch native --so libnative.so --offset 0x1234 --bytes "00"  # Native patch
python apk_cli.py patch find-insn --dex classes.dex --opcode "const/4"         # Cari instruksi
```

### Repack & Verifikasi

```bash
python apk_cli.py repack --apk original.apk --out modified.apk    # Repack APK
python apk_cli.py verify --apk modified.apk                        # Verifikasi di device
```

### Security Scanning

```bash
python apk_cli.py scan leaks ./project           # Scan kebocoran identitas
python apk_cli.py scan tls target.apk            # Cek TLS/certificate
python apk_cli.py scan signatures target.apk     # Analisis signature
```

### Frida / Analisis Dinamis

```bash
python apk_cli.py frida probe com.app            # Four-layer universal probe
python apk_cli.py frida spawn com.app             # Spawn-patch-detach
python apk_cli.py frida rpc com.app               # RPC server
python apk_cli.py frida-gen --template ssl-unpin --out bypass.js    # Generate bypass
python apk_cli.py frida-gen --template crypto-monitor --out crypto.js
```

### MITM & Debloat

```bash
python apk_cli.py mitm --apk target.apk --inspect-only             # Inspeksi sertifikat
python apk_cli.py mitm --export-frida ssl_unpin.js                  # Export bypass Frida
python apk_cli.py debloat --target ./unpacked --scan                # Scan SDK iklan
python apk_cli.py debloat --target ./unpacked --neuter              # Neuter komponen iklan
```

### JNI & Native

```bash
python apk_cli.py jni --so libnative.so --generate-hooks --out hook.js  # Hook generator
```

### Dekripsi & Decoding

```bash
python apk_cli.py decode blob --file config.bin --out clean.json         # Decode opaque config blob
python apk_cli.py decode proto --hex "08 96 01 12 07 74 65 73 74 69 6e 67" # Decode raw protobuf
```

### Web Reverse Engineering

```bash
python apk_cli.py web sourcemap --url https://target.com/app.min.js --out-dir ./src
python apk_cli.py web api-tracer --file ./src/app.js --json
python apk_cli.py web deobf --file bundle.min.js --output bundle.clean.js
python apk_cli.py web userscript --domain target.com --template bypass-anti-debug
python apk_cli.py web serve --port 8080 --map-local "/app.js=./clean.js"
```

### Laporan

```bash
python apk_cli.py report --apk target.apk --format markdown --out report.md
python apk_cli.py report --apk target.apk --format html --out report.html
python apk_cli.py report --apk target.apk --format json --out report.json
python apk_cli.py report --apk target.apk --format all --out-dir ./reports
```

---

## 📂 Struktur Direktori Lengkap

```
apk-reverse/
│
├── 📄 apk_cli.py                ← CLI terpadu — satu titik masuk untuk 65+ script
├── 📄 setup.py                  ← Installer otomatis (cek Python, deps, tools)
├── 📄 config.example.yaml       ← Template konfigurasi (Bahasa Indonesia)
├── 📄 requirements.txt          ← Dependensi Python
├── 📄 CHANGELOG.md              ← Riwayat perubahan
├── 📄 LICENSE                   ← MIT License
├── 📄 README.md                 ← Dokumentasi ini
├── 📄 README.zh-CN.md           ← README 简体中文
│
├── 📁 skills/                   ← 8 Agent Skills
│   │
│   ├── 📁 apk-reverse/         ← ⭐ Skill utama reverse engineering
│   │   ├── 📄 SKILL.md         ← Prosedur 4-gate + symptom index (48 KB)
│   │   ├── 📁 scripts/         ← 65+ script Python/JS
│   │   │   ├── doctor.py       ← Capability report (jalankan pertama!)
│   │   │   ├── dexutil.py      ← DEX reader dependency-free
│   │   │   ├── dex_patch_bytes.py  ← Equal-length byte patch
│   │   │   ├── repack.py       ← Rebuild + align + sign APK
│   │   │   ├── frida_probe.js  ← Four-layer runtime probe
│   │   │   ├── scan_leaks.py   ← Leak scanner
│   │   │   └── ... (60+ lainnya)
│   │   ├── 📁 references/      ← 46 dokumen teknis
│   │   │   ├── pitfalls.md     ← Katalog kegagalan (63 KB, paling berharga!)
│   │   │   ├── toolchain.md    ← Panduan tool lengkap
│   │   │   ├── routing.md      ← Inventaris on-demand
│   │   │   └── ... (43 lainnya)
│   │   ├── 📁 evidence/        ← capability-matrix.json, tested-tool-versions.json
│   │   └── 📁 evals/           ← Evaluation cases
│   │
│   ├── 📁 frida-dynamic-toolkit/  ← Instrumentasi & hook Frida
│   │   ├── 📄 SKILL.md
│   │   ├── 📁 scripts/         ← generate_bypass.py, crypto_monitor.py, jni_hook_scaffold.py
│   │   └── 📁 references/      ← ssl-pinning-matrix.md, root-detection-matrix.md
│   │
│   ├── 📁 apk-debloater/       ← Penghapusan iklan & telemetry
│   │   ├── 📄 SKILL.md
│   │   ├── 📁 scripts/         ← debloat_manifest.py, ad_stub_gen.py
│   │   └── 📁 references/      ← ad-signature-catalogue.md, manifest-neutering.md
│   │
│   ├── 📁 apk-mitm-patcher/    ← Intersepsi HTTPS & NSC
│   │   ├── 📄 SKILL.md
│   │   ├── 📁 scripts/         ← mitm_patch.py, cert_inspect.py
│   │   └── 📁 references/      ← network-security-config-deepdive.md
│   │
│   ├── 📁 apk-repacker/        ← Repack & signing pipeline
│   │   ├── 📄 SKILL.md
│   │   ├── 📁 scripts/         ← repack_pipeline.py, apk_signer.py
│   │   └── 📁 references/      ← apk-signing-schemes.md, zipalign-and-compression.md
│   │
│   ├── 📁 cf-bypass/           ← ☁️ Bypass Cloudflare Turnstile, IUAM, & WAF
│   │   ├── 📄 SKILL.md         ← Manual arsitektur 15 bab (35 KB)
│   │   ├── 📁 scripts/         ← cf_detector.py, turnstile_api_solver.py, cf_origin_finder.py
│   │   └── 📁 references/      ← 8 dokumen teknis TLS JA4, HTTP/2, Turnstile internals
│   │
│   ├── 📁 web-reverse/         ← 🌐 Reverse Engineering Web, Webpack & AST
│   │   ├── 📄 SKILL.md         ← Manual deobfuscasi, anti-debug & bundle unpacking (34.6 KB)
│   │   ├── 📁 scripts/         ← sourcemap_extractor.py, webpack_unpacker.py, js_deobfuscator.py
│   │   └── 📁 references/      ← 4 dokumen AST, Webpack internals, WASM, & API signing
│   │
│   └── 📁 web-security-audit/  ← 🛡️ Audit OWASP Top 10, Security Headers & Secret Scanner
│       ├── 📄 SKILL.md         ← Manual audit defensif 15 bab (30.2 KB)
│       ├── 📁 scripts/         ← security_headers_audit.py, cors_audit.py, secret_scanner.py
│       └── 📁 references/      ← 8 dokumen OWASP, CSP Level 3, Laravel & Database hardening
│
├── 📁 tests/                    ← Unit, integration, CLI tests
│   ├── 📄 README.md            ← Penjelasan split testing
│   ├── 📄 benchmark.md         ← Regression matrix (15 KB)
│   ├── 📄 conftest.py          ← Pytest fixtures
│   ├── 📄 test_so_constpatch.py ← Test .so patching (29 KB)
│   ├── 📁 unit/                ← 7 unit tests
│   ├── 📁 integration/         ← 3 integration tests
│   └── 📁 cli/                 ← 2 CLI contract tests
│
├── 📁 docs/                     ← Verifikasi tool
│   └── 📁 tool-verification/   ← Evidence record per measurement pass
│
├── 📁 assets/                   ← Banner SVG (dark/light)
│
├── 📁 .github/workflows/       ← CI/CD GitHub Actions
│
├── 📄 check_repo.py            ← Validasi skill, path, leak scan
├── 📄 check_refs.py            ← Cross-reference checker
├── 📄 check_routing.py         ← Inventaris masih cocok dengan entry point
├── 📄 check_commands.py        ← Perintah di dokumen vs argparse script
├── 📄 check_budget.py          ← Ukur SKILL.md agar tidak membengkak
├── 📄 build_scripts.py         ← Audit leftover (paths, credentials)
│
├── 📄 .flake8                  ← Linting rules
├── 📄 mypy.ini                 ← Type checking config
├── 📄 pytest.ini               ← Test runner config
├── 📄 .gitignore               ← Ignore patterns
└── 📄 .gitattributes           ← Git attributes
```

---

## 📝 Prasyarat

Tidak ada yang wajib — setiap script memeriksa apa yang dibutuhkan. Jalankan `doctor.py` untuk laporan lengkap.

| Tool | Wajib? | Kegunaan |
|------|--------|----------|
| Python 3.9+ | ✅ Ya | Runtime semua script |
| **`droidasc` (ASC)** | ⭐ Sangat disarankan | Index cross-reference APK — sub-second query tanpa full decompile |
| **`ddc`** | ⭐ Sangat disarankan | Single-binary dex→Java decompiler dengan query subcommands |
| `baksmali` / `smali` | ⚙️ Untuk patching | Disassembly/assembly DEX |
| JDK (`javac`, `java`) | ⚙️ Untuk patching | Build dexlib2 patcher, `keytool`/`jarsigner` |
| Android SDK build-tools | ⚙️ Untuk repack | `aapt`, `zipalign`, **`apksigner`** (signer yang benar) |
| `uber-apk-signer` | 💡 Opsional | One-step align + sign |
| ADB | ⚙️ Untuk device | Komunikasi dengan device |
| Frida (host + device) | 💡 Opsional | Analisis dinamis |
| Rooted device/emulator | 💡 Opsional | Untuk apapun di luar analisis statis |

> 💡 **Tips:** Jika tools ada tapi tidak di `PATH`, set `APKREV_TOOLS` ke direktori tools:
> ```bash
> set APKREV_TOOLS=C:\tools\android;C:\tools\java  # Windows
> export APKREV_TOOLS=/opt/android-sdk:/opt/tools   # Linux/macOS
> ```

---

## 🏗️ Maintenance Repository

6 tool di root untuk menjaga kualitas repository (bukan bagian skill):

| Tool | Fungsi |
|------|--------|
| `check_repo.py` | Validasi semua skill, frontmatter, script, path, dan scan identitas target |
| `check_refs.py` | Setiap cross-reference mengarah ke heading yang benar-benar ada |
| `check_routing.py` | Inventaris on-demand masih cocok dengan entry point |
| `check_commands.py` | Perintah di dokumen di-check terhadap argparse script-nya |
| `check_budget.py` | Ukur SKILL.md agar tidak membengkak (lines + tokens) |
| `build_scripts.py` | Audit machine-specific leftover (absolute paths, credentials) |

---

## 🧪 Testing

```bash
# Jalankan semua test
python -m pytest tests/

# Unit tests saja
python -m pytest tests/unit/

# Integration tests (tanpa device)
python -m pytest tests/integration/

# CLI contract tests
python -m pytest tests/cli/

# Test spesifik
python -m pytest tests/unit/test_dexutil.py -v
```

Regression matrix untuk target nyata tersedia di `tests/benchmark.md`.

---

## 📊 Statistik Repository

| Metrik | Jumlah |
|--------|--------|
| Total script | **95+** |
| Dokumen referensi | **80+** |
| Agent skills | **8** |
| Cakupan Keamanan | **Android APK, Cloudflare WAF, Web Reverse, Web Security Audit** |
| Unit tests | **7** |
| Integration tests | **3** |
| CLI tests | **2** |
| Maintenance tools | **6** |
| Bahasa README | **3** (ID, ZH-CN, EN) |
| Ukuran SKILL.md (apk-reverse) | **48 KB** |
| Ukuran SKILL.md (cf-bypass) | **35 KB** |
| Ukuran SKILL.md (web-reverse) | **34.6 KB** |
| Ukuran SKILL.md (web-security-audit) | **30.2 KB** |
| Ukuran pitfalls.md | **63 KB** |
| Ukuran repack.py | **65 KB** |
| Ukuran vmp_diff_harness.py | **73 KB** |

---

## ⚠️ 4 Kesalahan Paling Mahal

> Baca `skills/apk-reverse/references/pitfalls.md` sebelum mulai bekerja — setiap entry adalah kegagalan yang menghasilkan artifact rusak sambil terlihat sempurna.

1. **Strip seluruh `META-INF/`** saat repack → menghapus ServiceLoader registrations → app mati saat startup dengan error yang menyebutkan library yang tidak terkait.

2. **Patch string tanpa menjaga ordering `string_ids`** → seluruh DEX ditolak, padahal checksum dan signature verify sempurna.

3. **Rebuild DEX dengan smali round-trip** → merusak output R8 secara tak terlihat — class tables terlihat bersih, tapi meledak saat runtime.

4. **Neutralise native terminate dengan membuatnya *tidak return*** → stub spinning tidak menekan check; caller dan semua thread di belakangnya freeze. App hang tanpa crash record, dan kematian akhirnya disalahkan ke hal lain.

---

## 📜 Lisensi & Kredit

- **Lisensi Asli:** [MIT](LICENSE) — Hak Cipta (c) 2026 apk-reverse contributors.
- **Pengembangan & Modifikasi:** Dimodifikasi oleh **ALDY** (npx CLI runner, distribusi AI Agent Skills, Web Reverse Toolkit, dan dokumentasi).


---

## ⚠️ Disclaimer

**Hanya untuk pembelajaran, riset, dan pengujian keamanan yang diotorisasi.**

- **Target yang diotorisasi saja.** Gunakan pada aplikasi milik Anda sendiri, materi CTF/challenge publik, atau sandbox yang Anda kontrol. Menganalisis software tanpa hak mungkin melanggar hukum di wilayah Anda.
- **Tanpa garansi.** Material disediakan *apa adanya*, tanpa jaminan apapun. Hasil direkam sebagaimana diukur pada satu mesin pada satu waktu.
- **Verifikasi sebelum trust; backup sebelum bertindak.** Beberapa script memodifikasi artifact (DEX, APK, `.so`, data app) dan beroperasi di device rooted.
- **Penggunaan Anda adalah tanggung jawab Anda.** Penulis tidak bertanggung jawab atas kerugian, konsekuensi hukum, atau gangguan layanan.
- **Data target tidak didistribusikan.** Sample, dump, dan artifact device tidak ada di repository ini.
- **Tidak berafiliasi.** Nama tool, library, dan target publik muncul hanya untuk membuat material bisa digunakan kembali.

---

<p align="center">
  Proudly supported by the <a href="https://linux.do">LINUX DO</a> community.
</p>
