---
name: web-security-audit
description: "Audit, analyze, and harden web applications against OWASP Top 10 vulnerabilities, security header misconfigurations, insecure CORS policies, template XSS risks, and secret leaks. Features automated HTTP response header grading (CSP, HSTS, X-Frame-Options), CORS reflection analysis, cookie flag audits (HttpOnly/Secure/SameSite), and static code analysis for Laravel/PHP/JS projects with instant remediation recipes."
license: MIT
compatibility: "Python 3.9+, PHP 8.x, Node.js 18+. Compatible with Laravel, Nginx, Apache, and Express.js."
metadata:
  version: "2.0"
  reference_tools:
    - "scripts/security_headers_audit.py"
    - "scripts/cors_audit.py"
    - "scripts/static_code_audit.py"
    - "scripts/secret_scanner.py"
    - "scripts/csrf_audit.py"
  reference_manuals:
    - "references/owasp-secure-headers-guide.md"
    - "references/cors-hardening-playbook.md"
    - "references/laravel-security-hardening-bible.md"
    - "references/owasp-top-10-defensive-manual.md"
    - "references/api-security-and-jwt-hardening.md"
    - "references/secure-file-upload-architecture.md"
    - "references/content-security-policy-deep-dive.md"
    - "references/database-and-orm-hardening.md"
  standards_referenced:
    - "OWASP Secure Headers Project"
    - "OWASP Top 10 Web Application Security Risks (2021)"
    - "OWASP API Security Top 10 (2023)"
    - "W3C Content Security Policy Level 3"
    - "RFC 6265bis (Cookies: HTTP State Management Mechanism)"
    - "RFC 6454 (The Web Origin Concept)"
  last_reconstruction_pass: "2026-10-06"
---

# Web Application Security Audit, Defensive Hardening & Verification — Master Manual

Panduan ini adalah manual operasional tingkat lanjut untuk mengaudit postur pertahanan, memindai kerentanan keamanan web, mendeteksi kebocoran kredensial, dan menerapkan pengerasan (*hardening*) menyeluruh pada aplikasi web modern, REST/GraphQL API, serta arsitektur framework (khususnya Laravel, Node.js/Express, Nginx, dan Apache).

Skill ini berfokus pada **audit pertahanan preventif (defensive engineering), kepatuhan OWASP, eliminasi celah konfigurasi, dan otomatisasi verifikasi mitigasi**.

---

## DAFTAR ISI

1. [Aturan Pertahanan Kritis (Rules R1 - R12)](#1-aturan-pertahanan-kritis-rules-r1---r12)
2. [Alur Kerja Audit Keamanan Komprehensif (6 Fase)](#2-alur-kerja-audit-keamanan-komprehensif-6-fase)
3. [Audit & Skoring HTTP Security Headers (Grade A+ s/d F)](#3-audit--skoring-http-security-headers-grade-a-sd-f)
4. [Content Security Policy (CSP Level 3) & Nonce Architecture](#4-content-security-policy-csp-level-3--nonce-architecture)
5. [Audit & Hardening Cross-Origin Resource Sharing (CORS)](#5-audit--hardening-cross-origin-resource-sharing-cors)
6. [Standar Keamanan Sesi Cookie & Cookie Prefixes](#6-standar-keamanan-sesi-cookie--cookie-prefixes)
7. [Analisis Statis Kode & Pemindai Kebocoran Secret (Shannon Entropy)](#7-analisis-statis-kode--pemindai-kebocoran-secret-shannon-entropy)
8. [Arsitektur Proteksi CSRF & Validasi State-Change](#8-arsitektur-proteksi-csrf--validasi-state-change)
9. [Arsitektur File Upload Aman (Anti-RCE, Anti-Polyglot & SVG Sanitization)](#9-arsitektur-file-upload-aman-anti-rce-anti-polyglot--svg-sanitization)
10. [Database & ORM Hardening (SQLi Defense & Mass Assignment Prevention)](#10-database--orm-hardening-sqli-defense--mass-assignment-prevention)
11. [Keamanan API & JWT Hardening (OWASP API Top 10 & BOLA Defense)](#11-keamanan-api--jwt-hardening-owasp-api-top-10--bola-defense)
12. [Resep Pengerasan Per Framework & Web Server](#12-resep-pengerasan-per-framework--web-server)
    - Laravel 10 / 11 (SecurityHeadersMiddleware, CORS, Session, Blade)
    - Node.js / Express (Helmet, CORS, Rate Limit)
    - Nginx Server Block (Header Hardening, Upload Isolation, Dotfile Deny)
    - Apache (.htaccess / VirtualHost Hardening)
13. [Katalog Tools & Panduan Eksekusi Skrip CLI](#13-katalog-tools--panduan-eksekusi-skrip-cli)
14. [Matriks Diagnostik Kerentanan & Remediasi Cepat](#14-matriks-diagnostik-kerentanan--remediasi-cepat)
15. [Indeks Dokumen Referensi Teknis](#15-indeks-dokumen-referensi-teknis)

---

## 1. ATURAN PERTAHANAN KRITIS (RULES R1 - R12)

### R1 — Wajib Mengaktifkan HttpOnly, Secure, dan SameSite pada Cookie Autentikasi
Semua cookie autentikasi dan token sesi wajib memiliki atribut:
- `HttpOnly`: Mencegah script membaca cookie via `document.cookie` jika terjadi XSS.
- `Secure`: Memastikan cookie hanya dikirimkan melalui koneksi terenkripsi TLS/HTTPS.
- `SameSite=Lax` atau `SameSite=Strict`: Mencegah pengiriman cookie otomatis pada cross-site navigation (mitigasi utama CSRF).

### R2 — Cegah Clickjacking dengan X-Frame-Options atau CSP frame-ancestors
Aplikasi web tidak boleh diizinkan untuk di-embed ke dalam `<iframe>` pihak ketiga tanpa izin eksplisit. Gunakan `X-Frame-Options: DENY` atau `Content-Security-Policy: frame-ancestors 'self'`.

### R3 — Dilarang Menggabungkan `Access-Control-Allow-Origin: *` dengan Credentials
Jika API Anda mengizinkan kredensial autentikasi (`Access-Control-Allow-Credentials: true`), Anda **dilarang keras** menggunakan wildcard `*` atau memantulkan sembarang `Origin` yang dikirimkan oleh browser klien tanpa validasi whitelist domain tepercaya.

### R4 — Nonaktifkan Debug Mode dan Error Detail di Lingkungan Produksi
Pada framework seperti Laravel, pastikan `APP_DEBUG=false` di file `.env`. Mode debug membocorkan:
- Variabel environment lengkap (termasuk `DB_PASSWORD`, `APP_KEY`, API secret keys).
- Cuplikan baris kode backend dan database query trace.

### R5 — Wajib Sertakan Token CSRF pada Seluruh Form State-Changing
Setiap request HTTP yang mengubah state data (`POST`, `PUT`, `PATCH`, `DELETE`) wajib divalidasi dengan token anti-CSRF:
- Pada Laravel Blade: Selalu sisipkan direktif `@csrf` di dalam setiap elemen `<form>`.
- Pada SPA: Kirimkan header `X-XSRF-TOKEN` yang dicocokkan dengan cookie sesi terenkripsi.
- Larang penggunaan tautan GET (`<a href="/logout">` atau `<a href="/delete/1">`) untuk aksi perubahan data sensitif.

### R6 — Hindari Render Raw Output Tanpa Sanitasi pada Template
Pada template engine (Blade, Jinja, Twig):
- Gunakan sintaks otomatis escape `{{ $data }}` (menggunakan `htmlspecialchars`).
- Hindari penggunaan raw output `{!! $data !!}` untuk input pengguna kecuali telah dibersihkan secara ketat menggunakan HTMLPurifier.

### R7 — Hilangkan Header Kebocoran Informasi Versi Server
Server tidak boleh membocorkan versi teknologi backend kepada publik:
- Hapus header `X-Powered-By: PHP/8.x`.
- Sembunyikan versi server pada Nginx (`server_tokens off;`) dan Apache (`ServerTokens Prod; ServerSignature Off`).

### R8 — Terapkan Content-Type Nosniff untuk Mencegah MIME-Sniffing
Selalu kirimkan header `X-Content-Type-Options: nosniff`. Tanpa header ini, browser dapat mengeksekusi file gambar yang berisi payload script tersembunyi sebagai executable.

### R9 — Isolasi Direktori File Upload dari Eksekusi Script Server
Direktori yang digunakan untuk menampung file upload pengguna harus dikonfigurasi agar **menolak mengeksekusi script apa pun** (PHP, CGI, Python, JSP). Simpan file dengan nama acak kriptografis (UUID v4) di luar document root atau Object Storage (S3).

### R10 — Dilarang Menggunakan String Concatenation pada Raw Query ORM
Hindari penggunaan string variabel langsung di dalam `DB::raw()`, `whereRaw()`, atau `orderByRaw()`. Selalu gunakan prepared statement dengan parameter binding array: `whereRaw('status = ?', [$status])`.

### R11 — Validasi Otorisasi Objek (BOLA / IDOR Defense) pada Level Data-Layer
Jangan pernah mempercayai parameter ID dari klien tanpa memverifikasi kepemilikan objek terhadap sesi login pengguna: `auth()->user()->invoices()->findOrFail($id)`.

### R12 — Terapkan Rate Limiting Terdistribusi pada Endpoint Sensitif
Endpoint publik seperti `/login`, `/register`, `/api/password/reset`, dan endpoint komputasi berat wajib dilindungi oleh rate limiter dengan composite key (`IP + Username` atau `IP + User ID`).

---

## 2. ALUR KERJA AUDIT KEAMANAN KOMPREHENSIF (6 FASE)

```
[ Target URL / Direktori Codebase ]
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 1: AUDIT RESPON HEADER & COOKIE EKSTERNAL (LIVE)       │
│ - Jalankan `scripts/security_headers_audit.py --url <URL>`  │
│ - Evaluasi skor kepatuhan (A+ s/d F)                        │
│ - Deteksi header hilang: CSP, HSTS, X-Frame-Options         │
│ - Periksa kebocoran versi: `Server`, `X-Powered-By`         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 2: AUDIT KEBIJAKAN CROSS-ORIGIN (CORS AUDIT)           │
│ - Jalankan `scripts/cors_audit.py --url <API_URL>`          │
│ - Uji pantulan Origin acak, null origin, dan wildcard       │
│ - Verifikasi kombinasi berbahaya dengan credentials         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 3: AUDIT CSRF & MANIPULASI STATE HTTP                  │
│ - Jalankan `scripts/csrf_audit.py --url <URL>` (Live)       │
│ - Atau jalankan `scripts/csrf_audit.py --path <VIEWS_DIR>`  │
│ - Pindai form POST tanpa token dan aksi bahaya via GET      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 4: PEMINDAIAN STATIS KODE & SECRET LEAKS               │
│ - Jalankan `scripts/secret_scanner.py --path <PROJECT_DIR>` │
│ - Analisis string entropi tinggi dan kunci API ter-commit   │
│ - Jalankan `scripts/static_code_audit.py --path <DIR>`      │
│ - Audit raw output `{!!`, `APP_DEBUG`, dan fungsi eval()    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 5: AUDIT DATABASE ORM & POLA FILE UPLOAD               │
│ - Verifikasi whitelist `$fillable` pada seluruh Model       │
│ - Pindai potensi SQLi pada `whereRaw()` dan `orderByRaw()`  │
│ - Periksa penanganan upload: Re-encoding & Magic Bytes      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ FASE 6: GENERATE RESEP REMEDIASI & VERIFIKASI ULANG         │
│ - Generate config Nginx / Apache / Middleware Laravel       │
│ - Terapkan patch perbaikan pada codebase                    │
│ - Jalankan ulang audit hingga seluruh pengujian Grade A+    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. AUDIT & SKORING HTTP SECURITY HEADERS (GRADE A+ S/D F)

HTTP Security Headers adalah pertahanan lapis pertama (*first line of defense*) pada tingkat browser. Skrip `scripts/security_headers_audit.py` mengevaluasi header menggunakan formula pembobotan matematis standar OWASP:

| Header Keamanan | Bobot Nilai | Nilai Minimal Direkomendasikan |
|---|---|---|
| **Content-Security-Policy** | 25 Poin | `default-src 'self'; script-src 'self' ...; object-src 'none'` |
| **Strict-Transport-Security** | 20 Poin | `max-age=31536000; includeSubDomains; preload` |
| **X-Frame-Options** | 15 Poin | `DENY` atau `SAMEORIGIN` |
| **X-Content-Type-Options** | 15 Poin | `nosniff` |
| **Referrer-Policy** | 10 Poin | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | 10 Poin | `camera=(), microphone=(), geolocation=()` |
| **Cross-Origin-Opener-Policy** | 5 Poin | `same-origin` |

### Skala Penilaian Kepatuhan:
- **Grade A+ (95 - 100):** Seluruh header proteksi terpasang optimal, CSP ketat, HSTS preload aktif, tidak ada kebocoran versi.
- **Grade A (85 - 94):** Semua header vital hadir dengan konfigurasi aman.
- **Grade B (70 - 84):** Header dasar terpasang, namun CSP atau HSTS belum optimal.
- **Grade C (50 - 69):** Header penting seperti CSP atau X-Frame-Options tidak ditemukan.
- **Grade F (< 50):** Server tidak mengonfigurasi header proteksi sama sekali dan rentan terhadap clickjacking, XSS, dan sniffing.

---

## 4. CONTENT SECURITY POLICY (CSP LEVEL 3) & NONCE ARCHITECTURE

CSP Level 3 adalah standar mitigasi XSS terkuat saat ini. Alih-alih menggunakan domain whitelist yang rapuh, gunakan arsitektur berbasis **Cryptographic Nonce**:

```
[ HTTP Request Masuk ]
           │
           ▼
[ Security Middleware ]
 ├─ Generate acak: $nonce = base64_encode(random_bytes(16));
 ├─ Header: Content-Security-Policy: script-src 'nonce-$nonce' 'strict-dynamic';
 └─ Kirim $nonce ke View Renderer (Blade / React)
           │
           ▼
[ Browser Execution ]
 ├─ <script nonce="xyz">  --> DIJALANKAN (Valid Nonce)
 └─ <script>alert(1)</script> --> DIBLOKIR BROWSER (XSS Termitigasi!)
```

### Konfigurasi CSP Level 3 Standar Emas:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM_NONCE}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: blob:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;
```

---

## 5. AUDIT & HARDENING CROSS-ORIGIN RESOURCE SHARING (CORS)

Miskonfigurasi CORS memungkinkan situs web penyerang mengirimkan request cross-origin dan membaca respons data rahasia pengguna.

### Matriks Risiko CORS:
| Header yang Diberikan Server | Dampak Risiko |
|---|---|
| `Access-Control-Allow-Origin: *` pada Public API | **AMAN** jika API hanya menyajikan data publik tanpa autentikasi cookie. |
| `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` | **ILEGAL MENURUT SPESIFIKASI BROWSER** (Browser akan menolak respons). |
| `Access-Control-Allow-Origin: <Origin Penyerang>` (Reflected) + `Credentials: true` | **KRITIS** — Penyerang dapat mencuri data profil, saldo, dan informasi rahasia akun korban. |
| `Access-Control-Allow-Origin: null` + `Credentials: true` | **KRITIS** — Penyerang dapat mengeksploitasi iframe sandbox lokal (`origin: null`) untuk membaca data. |

### Pengujian Praktis via CLI:
```bash
python scripts/cors_audit.py --url http://127.0.0.1:8000/api/profile
```

---

## 6. STANDAR KEAMANAN SESI COOKIE & COOKIE PREFIXES

Semua cookie sesi wajib mematuhi standar **RFC 6265bis**:

```http
Set-Cookie: __Host-SessionId=a1b2c3d4...; Path=/; Secure; HttpOnly; SameSite=Lax
```

### Keunggulan Prefiks Cookie Aman:
1. **Prefiks `__Host-`:**
   - Wajib memiliki flag `Secure`.
   - Wajib berasal dari origin HTTPS.
   - Wajib memiliki `Path=/`.
   - **Dilarang** menyertakan atribut `Domain` (mencegah sub-domain yang diretas menimpa cookie domain utama).
2. **Prefiks `__Secure-`:**
   - Wajib dikirimkan melalui HTTPS dan memiliki flag `Secure`.

---

## 7. ANALISIS STATIS KODE & PEMINDAI KEBOCORAN SECRET (SHANNON ENTROPY)

Kebocoran API keys dan token pada commit Git atau source code frontend adalah penyebab utama pengambilalihan infrastruktur cloud.

### Fitur Pemindai `scripts/secret_scanner.py`:
- Memindai pola regex spesifik: AWS Keys (`AKIA...`), Stripe Secret (`sk_live_...`), GitHub PAT (`ghp_...`), private keys RSA/SSH, token Discord/Slack/Telegram.
- Menghitung **Shannon Entropy** untuk mendeteksi random cryptographic secret strings:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  String dengan $H(X) \ge 4.2$ ditandai sebagai kandidat secret yang perlu diinvestigasi.
- Mendeteksi file rahasia yang tidak boleh ter-commit: `.env`, `.env.backup`, `database.sqlite`, `id_rsa`.

### Pengujian Praktis:
```bash
python scripts/secret_scanner.py --path "C:/path/to/my-project" --max-size 2097152
```

---

## 8. ARSITEKTUR PROTEKSI CSRF & VALIDASI STATE-CHANGE

Cross-Site Request Forgery (CSRF) memaksa browser korban yang telah terautentikasi mengirimkan request berbahaya tanpa sepengetahuan korban.

### Aturan Verifikasi Skrip `scripts/csrf_audit.py`:
1. **Semua Form State-Changing (POST, PUT, DELETE):** Wajib menyertakan input tersembunyi `_token` atau direktif `@csrf`.
2. **Larangan State-Change via GET:** Tautan `<a href="/logout">` atau `<a href="/user/delete?id=1">` **wajib ditolak** dan diubah menjadi form POST.
3. **SPA & AJAX Header:** Halaman wajib menyertakan tag `<meta name="csrf-token">` untuk dikirimkan melalui header `X-CSRF-TOKEN` atau `X-XSRF-TOKEN`.

### Pengujian Praktis:
```bash
# Audit dinamis pada aplikasi live
python scripts/csrf_audit.py --url http://127.0.0.1:8000

# Audit statis pada direktori template Blade/HTML
python scripts/csrf_audit.py --path "C:/path/to/my-project/resources/views"
```

---

## 9. ARSITEKTUR FILE UPLOAD AMAN (ANTI-RCE, ANTI-POLYGLOT & SVG SANITIZATION)

Mengunggah file tanpa validasi ketat dapat mengakibatkan Remote Code Execution (RCE) via web shell. Terapkan arsitektur pertahanan 5 lapis:

1. **Ganti Nama File dengan UUID v4:** Jangan pernah menggunakan nama file yang dikirimkan oleh klien (`$file->getClientOriginalName()`) untuk mencegah Path Traversal (`../../shell.php`).
2. **Validasi Magic Bytes (Bukan Hanya Ekstensi):** Gunakan `finfo` atau `mime_content_type` biner.
3. **Re-encoding Gambar (GD/Imagick):** Gambar JPEG/PNG dibaca ulang dan digambar ke kanvas baru untuk melucuti payload PHP/JavaScript yang diselipkan pada komentar metadata EXIF (Polyglot File Attack).
4. **Sanitasi File SVG:** SVG berbasis XML dan dapat memuat `<script>` atau `<svg onload="...">` (Stored XSS). Gunakan sanitizer XML khusus atau tolak upload SVG dari pengguna umum.
5. **Isolasi Penyimpanan & Blokir Eksekusi Script:** Simpan file di luar public web root atau di S3, dan konfigurasi Nginx/Apache untuk memblokir eksekusi interpreter PHP pada folder upload.

---

## 10. DATABASE & ORM HARDENING (SQLI DEFENSE & MASS ASSIGNMENT PREVENTION)

### 10.1. Menghindari Bahaya Raw Query pada Eloquent
Jangan pernah menggabungkan string variabel ke dalam raw query:
```php
// BERBAHAYA (SQL Injection)
$users = DB::table('users')->whereRaw("username = '$username'")->get();

// AMAN (Prepared Statements dengan Parameter Binding)
$users = DB::table('users')->whereRaw("username = ?", [$username])->get();
```

### 10.2. Mitigasi Mass Assignment
- **DILARANG KERAS:** Menggunakan `protected $guarded = [];` pada Model Eloquent.
- **STANDAR AMAN:** Selalu gunakan whitelist `protected $fillable = ['name', 'email'];` dan validasi ketat via FormRequest.

---

## 11. KEAMANAN API & JWT HARDENING (OWASP API TOP 10 & BOLA DEFENSE)

### Mitigasi Vektor Serangan JWT:
1. **Kunci Algoritma Secara Statis:** Selalu tetapkan algoritma yang diizinkan (`['HS256']` atau `['RS256']`) untuk mencegah serangan `alg: none` dan Key Confusion.
2. **Simpan Token di Cookie HttpOnly:** Hindari menyimpan token autentikasi di `localStorage` karena rentan dicuri jika terjadi XSS.
3. **Pencegahan BOLA / IDOR:** Verifikasi otorisasi kepemilikan data langsung dari relasi user login:
   ```php
   // AMAN dari BOLA/IDOR
   $order = auth()->user()->orders()->findOrFail($orderId);
   ```

---

## 12. RESEP PENGERASAN PER FRAMEWORK & WEB SERVER

### A. Konfigurasi Nginx (`/etc/nginx/sites-available/default`)

```nginx
# 1. Pasang Security Headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none';" always;

# 2. Sembunyikan Versi Server
server_tokens off;

# 3. Blokir Akses ke File Tersembunyi (.env, .git)
location ~ /\.(?!well-known).* {
    deny all;
    return 404;
}

# 4. Blokir Eksekusi PHP di Folder Upload
location ^~ /storage/uploads/ {
    location ~* \.(php|phtml|phar|pl|py|jsp|sh|cgi)$ {
        deny all;
        return 404;
    }
}
```

### B. Konfigurasi Apache (`.htaccess`)

```apache
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none';"
    Header unset X-Powered-By
</IfModule>

ServerSignature Off
ServerTokens Prod

# Blokir Akses File Sensitif
<FilesMatch "^\.(env|git|htaccess)">
    Order allow,deny
    Deny from all
</FilesMatch>
```

### C. Middleware Laravel (`app/Http/Middleware/SecurityHeadersMiddleware.php`)

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
        
        if ($request->isSecure()) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        }

        $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none';");
        $response->headers->remove('X-Powered-By');

        return $response;
    }
}
```

---

## 13. KATALOG TOOLS & PANDUAN EKSEKUSI SKRIP CLI

Semua tool audit terletak di dalam subdirektori `scripts/`:

| Skrip | Fungsi & Cakupan Pemeriksaan |
|---|---|
| [`security_headers_audit.py`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/scripts/security_headers_audit.py) | Memeriksa seluruh response headers, cookie flags, kebocoran versi server, dan men-generate konfigurasi Nginx/Apache/Laravel otomatis. |
| [`cors_audit.py`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/scripts/cors_audit.py) | Menguji pantulan origin acak, null origin, wildcard credentials, dan preflight OPTIONS pada endpoint API. |
| [`static_code_audit.py`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/scripts/static_code_audit.py) | Memindai source code lokal (.env, Blade, PHP, JS) untuk debug mode aktif, fungsi berbahaya (`eval`), dan form tanpa CSRF. |
| [`secret_scanner.py`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/scripts/secret_scanner.py) | Memindai kebocoran kunci API, private keys, database URI, dan string entropi tinggi (Shannon Entropy) pada repository. |
| [`csrf_audit.py`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/scripts/csrf_audit.py) | Mengaudit form POST yang kehilangan token CSRF, link GET state-changing berbahaya, dan SameSite cookie flags. |

### Contoh Pemanggilan CLI:
```bash
# 1. Audit Header & Keamanan Cookie URL Hidup
python scripts/security_headers_audit.py --url http://127.0.0.1:8000

# 2. Audit CORS Endpoint API
python scripts/cors_audit.py --url http://127.0.0.1:8000/api/user

# 3. Audit CSRF pada Template Tampilan
python scripts/csrf_audit.py --path "C:/path/to/project/resources/views"

# 4. Pindai Kunci API & Secret Bocor
python scripts/secret_scanner.py --path "C:/path/to/project" --json secrets_report.json

# 5. Pindai Kerentanan Statis Codebase
python scripts/static_code_audit.py --path "C:/path/to/project" --severity HIGH
```

---

## 14. MATRIKS DIAGNOSTIK KERENTANAN & REMEDIASI CEPAT

| Temuan Audit | Kategori Risiko | Dampak Eksploitasi | Resep Remediasi Langsung |
|---|---|---|---|
| **Missing CSP Header** | HIGH | XSS pihak ketiga dapat mengeksekusi script jahat di browser pengguna. | Pasang header `Content-Security-Policy: default-src 'self' ...`. |
| **Missing X-Frame-Options** | HIGH | Clickjacking via iframe transparan. | Pasang `X-Frame-Options: DENY` atau CSP `frame-ancestors 'self'`. |
| **Cookie Sesi Tanpa HttpOnly** | CRITICAL | Script XSS dapat mencuri sesi login korban via `document.cookie`. | Setel `'http_only' => true` di `config/session.php`. |
| **Cookie Sesi Tanpa Secure** | HIGH | Sesi dapat di-sniff pada jaringan publik tidak terenkripsi. | Setel `'secure' => true` di `config/session.php`. |
| **SameSite=None Tanpa Secure** | HIGH | Browser menolak atau mengizinkan transmisi cross-site tanpa proteksi. | Ubah ke `SameSite=Lax` atau `SameSite=Strict`. |
| **Reflected CORS + Credentials** | CRITICAL | Situs penyerang dapat membaca respons API sensitif pengguna. | Whitelist hanya domain resmi di `config/cors.php`. |
| **`APP_DEBUG=true` di Produksi** | CRITICAL | Membocorkan kunci rahasia, database password, dan kode internal saat error. | Ubah menjadi `APP_DEBUG=false` di `.env`. |
| **Form POST Tanpa `@csrf`** | HIGH | Penyerang dapat memalsukan aksi submit form pengguna (CSRF). | Sisipkan direktif `@csrf` pada elemen form. |
| **Aksi Logout/Delete via GET Link** | MEDIUM | Dapat dipicu otomatis via tag `<img src="...">` penyerang. | Ubah rute menjadi form `POST` dengan token CSRF. |
| **SQLi pada Raw Query ORM** | CRITICAL | Penyerang dapat membaca, mengubah, atau menghapus seluruh database. | Gunakan prepared statement parameter binding `whereRaw('col = ?', [$val])`. |
| **Unrestricted File Upload** | CRITICAL | Unggah file `.php` menghasilkan Remote Code Execution (RCE). | Whitelist ekstensi, verifikasi magic bytes, re-encode gambar via GD, dan isolasi folder upload. |
| **Secret Bocor di Repository** | CRITICAL | Akun cloud (AWS, Stripe, Database) dapat dibobol dan disalahgunakan. | Revoke/rotasi kunci seketika, pindahkan ke `.env`, dan bersihkan riwayat Git. |

---

## 15. INDEKS DOKUMEN REFERENSI TEKNIS

Untuk petunjuk arsitektur dan panduan pengerasan mendalam, pelajari manual teknis berikut di direktori `references/`:

1. [`owasp-secure-headers-guide.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/owasp-secure-headers-guide.md) — Panduan mendalam konfigurasi HTTP Security Headers dan mitigasi serangan berbasis browser.
2. [`cors-hardening-playbook.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/cors-hardening-playbook.md) — Buku panduan konfigurasi CORS yang aman dan teknik pencegahan Arbitrary Origin Reflection.
3. [`laravel-security-hardening-bible.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/laravel-security-hardening-bible.md) — Manual pengerasan komprehensif khusus untuk arsitektur Laravel 10 dan 11.
4. [`owasp-top-10-defensive-manual.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/owasp-top-10-defensive-manual.md) — Analisis defensif dan strategi mitigasi untuk 10 risiko keamanan web terbesar versi OWASP.
5. [`api-security-and-jwt-hardening.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/api-security-and-jwt-hardening.md) — Panduan pengamanan REST/GraphQL API, arsitektur token JWT yang aman, mitigasi BOLA/IDOR, dan rate limiting.
6. [`secure-file-upload-architecture.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/secure-file-upload-architecture.md) — Arsitektur sistem file upload defensif, pencegahan RCE web shell, pemusnahan polyglot, dan isolasi web server.
7. [`content-security-policy-deep-dive.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/content-security-policy-deep-dive.md) — Panduan lengkap CSP Level 3, implementasi nonce kriptografis, mode Report-Only, dan eliminasi risiko XSS.
8. [`database-and-orm-hardening.md`](file:///c:/apk-reverse/apk/.agents/skills/web-security-audit/references/database-and-orm-hardening.md) — Panduan pengerasan database server, pencegahan SQL Injection pada ORM Eloquent/PDO, dan eliminasi celah Mass Assignment.
