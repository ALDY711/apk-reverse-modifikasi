# REST & GraphQL API Security, JWT Hardening, and Rate Limiting Manual

Panduan teknis mendalam untuk mengamankan Application Programming Interfaces (REST & GraphQL), menerapkan autentikasi berbasis JSON Web Token (JWT) yang tahan manipulasi, mencegah kerentanan Broken Object Level Authorization (BOLA/IDOR), serta membangun arsitektur rate limiting terdistribusi berbasis Redis.

---

## 1. OWASP API SECURITY TOP 10 (ANALISIS & PERTAHANAN)

| Kategori OWASP | Kerentanan | Vektor Serangan | Strategi Pertahanan Defensif |
|---|---|---|---|
| **API1:2023** | **BOLA (Broken Object Level Authorization)** | Penyerang mengganti ID entitas (`/api/orders/105` -> `/api/orders/106`) untuk mengakses data pengguna lain. | Wajib validasi kepemilikan objek pada level data-layer (Policy/Gate), jangan pernah mempercayai parameter ID tanpa pengecekan konteks sesi `auth()->id()`. |
| **API2:2023** | **Broken Authentication** | Credential stuffing, brute force token, algoritma token lemah (`alg: none`), token kedaluwarsa tidak diverifikasi. | Validasi JWT ketat (algoritma tetap, validasi klaim `exp`/`iss`/`aud`), refresh token rotation, proteksi brute-force dengan exponential backoff. |
| **API3:2023** | **BOPL (Broken Object Property Level Authorization)** | Mass assignment pada JSON request body untuk mengubah status (`is_admin: true`) atau field sensitif (`balance`). | Gunakan DTO (Data Transfer Object) atau whitelist field (`$fillable` pada Laravel, Joi/Zod schema pada Node.js). Jangan pernah gunakan input request mentah. |
| **API4:2023** | **Unrestricted Resource Consumption** | Penyerang membanjiri endpoint berat (export PDF, query pencarian kompleks, kompresi zip) menyebabkan denial of service (DoS). | Terapkan rate limiting per IP + User ID, pagination wajib (`limit` maks 100), batas ukuran payload request (`client_max_body_size`), timeout eksekusi query. |
| **API5:2023** | **BFLA (Broken Function Level Authorization)** | Pengguna biasa memanggil endpoint administratif (`/api/v1/admin/users/delete`) karena izin hanya dicek di frontend. | RBAC (Role-Based Access Control) terpusat pada middleware backend, verifikasi role/permission di setiap route handler, tolak akses secara default (*deny-by-default*). |
| **API6:2023** | **Unrestricted Access to Sensitive Business Flows** | Bot memborong stok tiket/flash sale, scraping harga massal, atau memposting ulasan palsu secara otomatis. | Deteksi otomasi (bot scoring, Turnstile/reCAPTCHA v3), batasi frekuensi aksi bisnis per akun, verifikasi 2FA/OTP untuk alur kritis. |
| **API7:2023** | **Server-Side Request Forgery (SSRF)** | API menerima URL untuk webhook atau import avatar, lalu server backend melakukan fetch ke internal metadata cloud (`http://169.254.169.254`). | Larang pemanggilan IP privat (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`, loopback `127.0.0.1`), gunakan DNS resolution whitelist. |
| **API8:2023** | **Security Misconfiguration** | CORS terlalu permisif, verbose error stack trace, HTTP method tidak aman aktif (`TRACE`, `DEBUG`), header keamanan hilang. | Nonaktifkan debug mode di produksi, terapkan header OWASP Secure Headers, konfigurasi CORS ketat untuk origin terdaftar, matikan method HTTP yang tidak digunakan. |
| **API9:2023** | **Improper Inventory Management** | Endpoint API versi lama (`/api/v1/`) yang sudah deprecated dan tidak ter-patch dibiarkan aktif tanpa autentikasi. | Decommissioning API lama secara terjadwal, dokumentasi OpenAPI/Swagger otomatis tersinkronisasi, blokir akses ke endpoint staging/test dari jaringan publik. |
| **API10:2023** | **Unsafe Consumption of APIs** | Backend mempercayai data dari integrasi pihak ketiga (misal: webhook payment gateway) tanpa verifikasi tanda tangan HMAC. | Verifikasi signature HMAC/ECDSA pada semua incoming webhook, validasi skema data respons pihak ketiga sebelum diproses atau disimpan ke database. |

---

## 2. ARSITEKTUR & HARDENING JSON WEB TOKEN (JWT)

JSON Web Token terdiri dari 3 segmen yang dipisahkan oleh titik: `Header.Payload.Signature` (Base64URL encoded).

```
[ HEADER ]             . [ PAYLOAD / CLAIMS ]    . [ SIGNATURE ]
{"alg":"HS256",...}      {"sub":"123","exp":...}    HMACSHA256(header + "." + payload, secret)
```

### 2.1. Mitigasi Vektor Serangan JWT

#### A. Serangan "None" Algorithm (`alg: none`)
- **Kerentanan:** Penyerang mengubah header menjadi `{"alg": "none"}` dan menghapus segmen signature. Jika parser JWT backend tidak memvalidasi algoritma, token tanpa signature akan diterima sebagai valid.
- **Remediasi:** Wajib tetapkan algoritma yang diizinkan secara eksplisit pada fungsi verifikasi backend. Jangan biarkan parser mendeteksi algoritma secara dinamis dari header token.

```php
// PHP (Firebase JWT) - Benar
$decoded = JWT::decode($token, new Key($secretKey, 'HS256')); // Mengunci algoritma ke HS256

// Node.js (jsonwebtoken) - Benar
jwt.verify(token, secretKey, { algorithms: ['HS256'] }); // Memaksa HS256
```

#### B. Serangan Kebingungan Kunci Algoritma Asimetris vs Simetris (Key Confusion / RS256 to HS256)
- **Kerentanan:** Server dirancang memverifikasi token bertanda tangan RS256 menggunakan Public Key RSA. Penyerang mengubah header menjadi `alg: "HS256"` dan menandatangani token menggunakan Public Key RSA publik (yang dapat diakses siapa saja) sebagai secret key HMAC. Jika verifier memeriksa algoritma secara longgar, verifikasi signature akan berhasil!
- **Remediasi:** Pastikan fungsi verifikasi secara kaku membedakan jenis kunci simetris dan asimetris serta memvalidasi tipe instance kunci.

```javascript
// Node.js - Proteksi Tegas Key Confusion
const fs = require('fs');
const publicKey = fs.readFileSync('public_key.pem');

// Kunci hanya boleh diverifikasi dengan RS256 dan Public Key
jwt.verify(token, publicKey, { 
    algorithms: ['RS256'],
    issuer: 'https://auth.company.com',
    audience: 'https://api.company.com'
});
```

#### C. Validasi Klaim Wajib (Standard Claims Verification)
Setiap verifikasi token wajib memvalidasi klaim-klaim berikut:
1. `exp` (Expiration Time): Wajib ada dan tidak boleh berada di masa lalu. Berikan nilai kedaluwarsa pendek untuk Access Token (15 - 60 menit).
2. `nbf` (Not Before): Token tidak valid sebelum waktu yang ditentukan.
3. `iat` (Issued At): Mencegah token dengan waktu terbit yang tidak masuk akal (toleransi clock skew maksimal 60 detik).
4. `iss` (Issuer): Memastikan token diterbitkan oleh server otentikasi internal Anda, bukan server luar.
5. `aud` (Audience): Memastikan token ditujukan untuk API spesifik Anda.

---

### 2.2. Pola Refresh Token Rotation & Deteksi Penggunaan Ulang (Reuse Detection)

Penyimpanan token jangka panjang tidak boleh menggunakan Access Token statis. Gunakan pola rotasi refresh token:

```
[ Client ]                        [ Auth Server ]                     [ Redis / Database ]
    │                                    │                                      │
    ├─── POST /api/token/refresh ───────>│                                      │
    │    (kirim RefreshToken_A)          ├─── Cek Status Token_A ──────────────>│
    │                                    │    (Valid & Belum Digunakan?)        │
    │                                    │<── OK (Valid) ───────────────────────┤
    │                                    │                                      │
    │                                    ├─── Invalidate Token_A (Revoke) ─────>│
    │                                    ├─── Simpan RefreshToken_B (Baru) ────>│
    │<── Return AccessToken + Token_B ───┤                                      │
    │                                    │                                      │
```

#### Mekanisme Deteksi Pembobolan (Token Reuse Detection):
Jika penyerang mencuri `RefreshToken_A` dan mencoba menggunakannya setelah korban telah menukarnya menjadi `RefreshToken_B`:
1. Server mendeteksi bahwa `RefreshToken_A` memiliki status **REVOKED/USED**.
2. **Alert Keamanan:** Ini menandakan token telah dicuri!
3. Server seketika mencabut seluruh *token family* milik pengguna tersebut (membatalkan `RefreshToken_B` dan semua active sessions).
4. Pengguna dipaksa login ulang dan diberi notifikasi email bahwa sesi mencurigakan terdeteksi.

---

### 2.3. Tempat Penyimpanan Token yang Aman pada Sisi Klien

| Metode Penyimpanan | Risiko XSS | Risiko CSRF | Rekomendasi |
|---|---|---|---|
| **localStorage** | **KRITIS** — Seluruh script JavaScript (termasuk library NPM pihak ketiga atau XSS payload) dapat membaca token via `localStorage.getItem('token')`. | Kebal CSRF (karena header disisipkan manual via JS). | **TIDAK DIREKOMENDASIKAN** untuk token sesi sensitif. |
| **sessionStorage** | **KRITIS** — Sama seperti localStorage, rentan dibaca oleh payload XSS. | Kebal CSRF. | Tidak direkomendasikan. |
| **HttpOnly, Secure Cookie** | **KEBAL XSS** — JavaScript di browser sama sekali tidak dapat mengakses nilai cookie. | Rentan jika tanpa proteksi CSRF. | **SANGAT DIREKOMENDASIKAN**, dengan syarat wajib menyertakan flag `SameSite=Lax` atau `SameSite=Strict` dan token anti-CSRF untuk request state-changing. |

---

## 3. PENCEGAHAN BOLA / IDOR (BROKEN OBJECT LEVEL AUTHORIZATION)

Kerentanan BOLA adalah salah satu ancaman API paling umum dan berbahaya. Penyerang cukup mengubah parameter `id` di URL untuk melihat atau memodifikasi data orang lain.

### 3.1. Anti-Pattern (Kode Rentan)

```php
// KODE RENTAN (Laravel Controller)
public function getInvoice($id)
{
    // BAHAYA: Mengambil invoice berdasarkan ID tanpa mengecek apakah invoice milik pengguna yang login!
    $invoice = Invoice::findOrFail($id);
    return response()->json($invoice);
}
```

```javascript
// KODE RENTAN (Express.js)
app.get('/api/users/:userId/orders', async (req, res) => {
    // BAHAYA: Hanya membaca req.params.userId tanpa membandingkan dengan req.user.id
    const orders = await db.orders.findAll({ where: { userId: req.params.userId } });
    res.json(orders);
});
```

### 3.2. Pola Defensif yang Benar

#### Menggunakan Relasi Langsung dari Autentikasi Pengguna:
```php
// SOLUSI 1: Query langsung dari relasi user yang sedang login
public function getInvoice($id)
{
    $invoice = auth()->user()->invoices()->findOrFail($id);
    return response()->json($invoice);
}
```

#### Menggunakan Authorization Policy / Gate:
```php
// SOLUSI 2: Menerapkan Laravel Policy
public function updateInvoice(Request $request, Invoice $invoice)
{
    $this->authorize('update', $invoice); // InvoicePolicy::update() memeriksa $user->id === $invoice->user_id
    
    $invoice->update($request->validated());
    return response()->json($invoice);
}
```

---

## 4. ARSITEKTUR RATE LIMITING & DOS MITIGATION

API publik wajib dilindungi dari serangan brute-force, scraping liar, dan resource exhaustion.

### 4.1. Algoritma Rate Limiting Populer

1. **Token Bucket:**
   - Bucket memiliki kapasitas tetap $B$ token.
   - Token diisi ulang dengan laju konstan $r$ token per detik.
   - Setiap request mengurangi 1 token. Jika bucket kosong, request ditolak (`429 Too Many Requests`).
   - *Kelebihan:* Mendukung burst traffic singkat yang wajar.

2. **Sliding Window Counter (Berbasis Redis):**
   - Menghitung jumlah request dalam interval waktu dinamis (misal 60 detik terakhir) menggunakan Redis Sorted Set (`ZSET`).
   - Timestamp request dicatat sebagai score.
   - Menghilangkan anomali spike di batas jendela waktu (*boundary condition* pada fixed window).

### 4.2. Implementasi Sliding Window Counter pada Redis

```lua
-- Script Redis Lua untuk Sliding Window Rate Limiting yang Aman & Atomik
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clearBefore = now - window

-- Hapus request yang berada di luar rentang window waktu
redis.call('ZREMRANGEBYSCORE', key, 0, clearBefore)

-- Hitung total request yang tersisa di window saat ini
local currentRequests = redis.call('ZCARD', key)

if currentRequests < limit then
    -- Tambahkan request baru dengan timestamp saat ini
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window)
    return 1 -- Izinkan request
else
    return 0 -- Tolak request (Rate limit exceeded)
end
```

### 4.3. Penentuan Composite Key untuk Rate Limiting

Jangan hanya mengandalkan alamat IP klien (`$request->ip()`), karena:
- Banyak pengguna kantor/kampus berada di balik NAT publik yang sama (IP sama).
- Penyerang terdistribusi menggunakan rotating proxy botnet.

**Gunakan Composite Key:**
- **Untuk pengguna login:** `rate_limit:user:{user_id}:{endpoint_hash}` (Limit lebih longgar, misal 300 req/menit).
- **Untuk pengguna anonim/tamu:** `rate_limit:ip:{client_ip}:{endpoint_hash}` (Limit lebih ketat, misal 60 req/menit).
- **Untuk endpoint sensitif (Login / Password Reset / OTP):** `rate_limit:auth:{client_ip}:{username_hash}` (Maksimal 5 percobaan gagal per 15 menit dengan lock delay).

---

## 5. STANDARD HEADER RESPON RATE LIMITING (RFC 6585 & IETF DRAFT)

Server wajib mengembalikan header respons berikut agar klien memahami status kuota:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 1728211260
Retry-After: 45

{
  "status": 429,
  "error": "Too Many Requests",
  "message": "Anda telah melampaui batas permintaan kuota API. Silakan coba lagi dalam 45 detik.",
  "retry_after_seconds": 45
}
```
