# Rate Limiting & Anti-Automation Hardening Bible

Panduan teknis defensif komprehensif untuk merancang, mengaudit, dan mengimplementasikan arsitektur **Rate Limiting**, mitigasi **Credential Stuffing**, proteksi **SMS OTP Toll Fraud**, dan pertahanan **Anti-Automation** pada aplikasi web modern dan REST API.

---

## 1. Taksonomi Ancaman Automasi & Pembobolan Brute-Force

Aplikasi web tanpa pembatas laju (*rate limiting*) rentan terhadap berbagai eksploitasi otomatis skala besar:

```
                                [Lalu Lintas Otomatis Jahat]
                                             │
      ┌──────────────────────┬───────────────┴───────────────┬──────────────────────┐
      ▼                      ▼                               ▼                      ▼
[Credential Stuffing]  [OTP SMS Toll Fraud]            [Sybil Registrations]  [Race Conditions Checkout]
Menembak jutaan akun   Menghabiskan saldo SMS          Membuat ribuan akun    Menembak kupon diskon
dengan bot proxy       via nomor premium berbayar      palsu untuk referral   secara paralel (concurrency)
```

---

## 2. Algoritma Pembatasan Laju (*Rate Limiting Algorithms*)

| Algoritma | Kelebihan | Kekurangan | Rekomendasi Kasus Penggunaan |
| :--- | :--- | :--- | :--- |
| **Fixed Window Counter** | Sederhana, hemat memori | Rentan *burst* di batas pergantian window (2x batas kuota). | Kurang disarankan untuk endpoint kritis. |
| **Token Bucket** | Mendukung burst legal, transmisi mulus | Sedikit lebih rumit | Standar API publik umum (Nginx, Stripe API). |
| **Sliding Window Log (Redis)** | Akurat 100%, eliminasi celah batas window | Memerlukan memori Redis untuk menyimpan timestamp | **Pilihan Utama** untuk alur Login, OTP, dan Keuangan. |

---

## 3. Strategi Composite Limiter Keys (Kunci Bertingkat)

Kesalahan fatal dalam implementasi pembatas laju adalah **hanya mengandalkan IP address**.
* Jika ribuan pengguna berada di balik NAT kantor/kampus yang sama, satu penyerang akan memblokir seluruh kantor.
* Jika penyerang menggunakan residential proxy botnet, pembatasan per IP menjadi tidak berguna.

### Formula Kunci Komposit yang Aman:
1. **Endpoint Login:**
   $$\text{Key} = \text{SHA256}(\text{IP}) + \text{":"} + \text{SHA256}(\text{Normalized Email})$$
   * Batasi maksimal 5 percobaan per menit per kombinasi IP + Email.
   * Batasi maksimal 50 percobaan per menit secara global per IP (menahan *distributed username spray*).
2. **Endpoint SMS / OTP:**
   $$\text{Key} = \text{Normalized Phone Number} + \text{":"} + \text{Country Code}$$
   * Batasi 3 pengiriman SMS per 10 menit per nomor telepon.
   * Batasi maksimal 10 SMS per jam per IP address.

---

## 4. Playbook Implementasi Produksi

### A. Arsitektur Redis Sliding Window (Node.js & Python)
Implementasi menggunakan Redis Sorted Set (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`):
```javascript
async function isRateLimited(redis, key, limit, windowSeconds) {
    const now = Date.now();
    const clearBefore = now - (windowSeconds * 1000);

    const multi = redis.multi();
    multi.zremrangebyscore(key, 0, clearBefore); // Hapus log kadaluwarsa
    multi.zadd(key, now, now.toString());        // Tambah percobaan saat ini
    multi.zcard(key);                            // Hitung jumlah percobaan dalam window
    multi.expire(key, windowSeconds);

    const results = await multi.exec();
    const requestCount = results[2][1];

    return requestCount > limit;
}
```

---

### B. Konfigurasi Nginx Web Server (Leaky Bucket Enforcement)
Terapkan pembatasan di lapisan reverse-proxy terdepan sebelum menyentuh aplikasi backend:

```nginx
# Di dalam blok http:
# 1. Zone khusus endpoint autentikasi (5 request per menit)
limit_req_zone $binary_remote_addr zone=auth_strict:10m rate=5r/m;

# 2. Zone umum API (30 request per detik)
limit_req_zone $binary_remote_addr zone=api_general:10m rate=30r/s;

# Di dalam blok server:
server {
    # Terapkan batas ketat pada login dan registrasi
    location ~* /(login|register|reset-password|send-otp) {
        limit_req zone=auth_strict burst=2 nodelay;
        limit_req_status 429;
        proxy_pass http://backend_app;
    }

    # Terapkan batas umum pada seluruh rute API
    location /api/ {
        limit_req zone=api_general burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://backend_app;
    }
}
```

---

### C. Laravel 10/11 Adaptive Throttling & Exponential Backoff
Konfigurasi pembatasan laju dinamis dengan penguncian bertingkat:

```php
// app/Providers/AppServiceProvider.php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Http\Request;

public function boot(): void {
    RateLimiter::for('login_adaptive', function (Request $request) {
        $key = 'login:' . $request->ip() . '|' . strtolower($request->input('email', ''));

        return Limit::perMinute(5)->by($key)->response(function (Request $request, array $headers) {
            return response()->json([
                'error' => 'Terlalu banyak percobaan masuk yang gagal.',
                'retry_after' => $headers['Retry-After'] ?? 60
            ], 429);
        });
    });

    RateLimiter::for('sms_verification', function (Request $request) {
        // Enforce 1 SMS per 60 detik per nomor, maksimal 3 per jam
        return [
            Limit::perMinutes(1, 1)->by('sms_min:' . $request->input('phone')),
            Limit::perHour(3)->by('sms_hr:' . $request->input('phone')),
        ];
    });
}
```

---

## 5. Pertahanan Berlapis (Defense-in-Depth Anti-Bot)

1. **Adaptive CAPTCHA Integration (Cloudflare Turnstile):**
   * Jangan tampilkan CAPTCHA pada percobaan pertama (menjaga User Experience).
   * Munculkan widget CAPTCHA hanya setelah pengguna gagal login 2 kali berturut-turut.
2. **Account Lockout dengan Exponential Backoff:**
   * 5 kegagalan berturut-turut: Kunci selama 1 menit.
   * 10 kegagalan: Kunci selama 15 menit dan kirimkan email peringatan keamanan ke pemilik akun.
   * 15 kegagalan: Wajibkan reset kata sandi via email.
3. **Pemberian Respon Seragam (*Constant-Time Responses*):**
   * Pastikan waktu respons server ketika akun ada vs akun tidak ada tetap identik untuk mencegah *User Enumeration* melalui teknik timing attack.
