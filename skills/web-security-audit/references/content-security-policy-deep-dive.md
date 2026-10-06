# Content Security Policy (CSP Level 3) — Deep Dive & Implementation Manual

Panduan teknis arsitektur pertahanan berbasis **Content Security Policy (CSP Level 3)** untuk memitigasi serangan Cross-Site Scripting (XSS), Data Injection, Clickjacking, dan pembajakan form submission pada aplikasi web modern.

---

## 1. ANATOMI & PRINSIP KERJA CSP LEVEL 3

Content Security Policy (CSP) adalah header respons HTTP yang memberi tahu browser klien domain atau sumber daya mana saja yang diizinkan untuk memuat dan mengeksekusi script, style sheet, gambar, frame, font, dan koneksi jaringan.

### Pola Sintaks Header:
```http
Content-Security-Policy: <directive> <source-expression>; <directive> <source-expression>; ...
```

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DIREKTIF-DIREKTIF INTI CSP                      │
├───────────────────┬────────────────────────────────────────────────────┤
│ default-src       │ Fallback default untuk semua direktif resource.    │
│ script-src        │ Mengatur sumber script JavaScript yang boleh jalan.│
│ style-src         │ Mengatur stylesheet CSS yang boleh dimuat.         │
│ img-src           │ Mengatur sumber gambar yang diizinkan.             │
│ connect-src       │ Mengatur endpoint XHR, fetch(), WebSocket, SSE.   │
│ font-src          │ Mengatur sumber web fonts (@font-face).            │
│ object-src        │ Mengatur plugin Flash/Java (Wajib 'none').         │
│ frame-ancestors   │ Mengontrol siapa yang boleh me-embed via <iframe>. │
│ form-action       │ Mengontrol URL target pengiriman data <form>.      │
│ base-uri          │ Mengunci tag <base href="..."> (Mencegah hijack).  │
│ upgrade-insecure- │ Memaksa semua request HTTP diubah otomatis ke      │
│ requests          │ HTTPS sebelum dikirim browser.                     │
└───────────────────┴────────────────────────────────────────────────────┘
```

---

## 2. ARSITEKTUR CSP BERBASIS CRYPTOGRAPHIC NONCE

Pendekatan lama CSP mengandalkan domain whitelist (`script-src https://trusted.com`), namun ini rentan di-bypass jika domain tersebut meng-host library yang memiliki JSONP endpoint atau gadget AngularJS/React.

**Standar Emas Modern:** Menggunakan **Cryptographic Nonce (Number Used Once)** yang di-generate unik per request HTTP.

### 2.1. Alur Nonce CSP

```
[ Request Masuk ]
       │
       ▼
[ Backend Middleware ]
 ├─ Generate acak: $nonce = base64_encode(random_bytes(16));
 ├─ Pasang Header:
 │   Content-Security-Policy: script-src 'nonce-$nonce' 'strict-dynamic';
 └─ Teruskan $nonce ke View Renderer (Blade / React / SSR)
       │
       ▼
[ Template HTML ]
 <script nonce="{{ $nonce }}">
     console.log("Script ini diizinkan dieksekusi!");
 </script>
 
 <script>
     // DIBLOKIR BROWSER KARENA TIDAK MEMILIKI ATRIBUT NONCE YANG COCOK!
     alert("XSS Payload Gagal!");
 </script>
```

### 2.2. Peran Direktif `'strict-dynamic'`
- Saat `'strict-dynamic'` dideklarasikan bersama `'nonce-...'`, script tepercaya yang memiliki atribut nonce diizinkan memuat script baru secara dinamis (`document.createElement('script')`) tanpa memerlukan deklarasi domain tambahan.
- Ini mempermudah integrasi library analitik modern seperti Google Tag Manager atau Webpack bundles tanpa perlu mematikan proteksi CSP.

---

## 3. IMPLEMENTASI MIDDLEWARE CSP NONCE PADA LARAVEL

### 3.1. Buat Middleware `ContentSecurityPolicyMiddleware.php`

```php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicyMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Generate nonce kriptografis 128-bit unik untuk setiap request
        $nonce = base64_encode(random_bytes(16));
        $request->attributes->set('csp_nonce', $nonce);

        /** @var Response $response */
        $response = $next($request);

        // Jangan terapkan CSP pada file download biner atau API non-HTML murni
        $contentType = $response->headers->get('Content-Type', '');
        if (!str_contains($contentType, 'text/html')) {
            return $response;
        }

        // 2. Susun direktif CSP ketat
        $cspDirectives = [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic' https: 'unsafe-inline'", // 'unsafe-inline' diabaikan oleh browser modern jika nonce ada (sebagai fallback untuk browser purba)
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data: https: blob:",
            "connect-src 'self' https:",
            "frame-ancestors 'self'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "upgrade-insecure-requests",
        ];

        $policy = implode('; ', $cspDirectives);

        // Gunakan Content-Security-Policy-Report-Only pada tahap testing awal
        $response->headers->set('Content-Security-Policy', $policy);

        return $response;
    }
}
```

### 3.2. Menyediakan Blade Helper / Directive untuk Nonce

Daftarkan di `AppServiceProvider.php`:

```php
use Illuminate\Support\Facades\Blade;

public function boot(): void
{
    Blade::directive('nonce', function () {
        return 'nonce="<?= request()->attributes->get(\'csp_nonce\') ?> "';
    });
}
```

Gunakan di dalam template Blade:

```html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Aplikasi Aman</title>
</head>
<body>
    <h1>Dashboard Pengguna</h1>

    <!-- Script lokal dengan nonce otomatis -->
    <script @nonce>
        document.addEventListener('DOMContentLoaded', () => {
            console.log('App terinisialisasi dengan aman di bawah proteksi CSP!');
        });
    </script>
</body>
</html>
```

---

## 4. STRATEGI ROLLOUT: DARI REPORT-ONLY KE STRICT ENFORCEMENT

Menerapkan CSP secara mendadak pada aplikasi yang sudah berjalan sering kali memicu error tampilan jika ada inline script yang belum di-nonce. Gunakan strategi **3 Fase**:

### Fase 1: Mode Observasi (`Content-Security-Policy-Report-Only`)
Kirimkan header laporan tanpa memblokir eksekusi script:

```http
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'nonce-xyz'; report-uri /api/csp-violations; report-to csp-endpoint
```

### Fase 2: Endpoint Kolektor Pelanggaran CSP (Violation Collector)

Tangkap laporan JSON yang dikirimkan oleh browser:

```php
// Route::post('/api/csp-violations', [SecurityReportController::class, 'handleCspReport']);

public function handleCspReport(Request $request)
{
    $data = $request->json()->all();
    
    \Log::warning('CSP Violation Report Diterima:', [
        'blocked_uri'      => $data['csp-report']['blocked-uri'] ?? null,
        'violated_directive' => $data['csp-report']['violated-directive'] ?? null,
        'document_uri'     => $data['csp-report']['document-uri'] ?? null,
        'line_number'      => $data['csp-report']['line-number'] ?? null,
        'user_agent'       => $request->userAgent(),
    ]);

    return response()->noContent();
}
```

### Fase 3: Mode Penegakan Penuh (Enforcement)
Setelah tidak ada lagi laporan violation dari fitur bisnis yang sah, ubah header menjadi `Content-Security-Policy` (tanpa `-Report-Only`).

---

## 5. CHECKLIST VERIFIKASI KEAMANAN CSP

- [ ] **`object-src 'none'` terpasang:** Mencegah pemuatan file Flash, ActiveX, atau Java applets.
- [ ] **`base-uri 'self'` terpasang:** Mencegah serangan HTML injection yang memanipulasi tag `<base href="https://attacker.com/">` untuk mengarahkan link relatif.
- [ ] **`frame-ancestors 'self'` atau domain terdaftar:** Menggantikan `X-Frame-Options` yang sudah deprecated di browser modern untuk mencegah clickjacking.
- [ ] **Tidak ada wildcard `'*'` pada `script-src`:** Seluruh eksekusi script harus terisolasi.
- [ ] **Hindari `'unsafe-eval'`:** Mencegah eksekusi `eval()`, `new Function()`, dan `setTimeout('string')`.
- [ ] **`form-action 'self'`:** Mencegah form injection yang mengubah atribut `<form action="https://attacker.com">` saat terjadi stored HTML injection.
