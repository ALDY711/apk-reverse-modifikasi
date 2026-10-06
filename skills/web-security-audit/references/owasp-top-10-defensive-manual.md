# OWASP Top 10 Web Security Defensive Engineering Manual

Manual referensi ini menjabarkan 10 risiko keamanan aplikasi web teratas menurut konsorsium **OWASP (Open Web Application Security Project)** beserta strategi mitigasi teknis dan pola pertahanan konkret pada kode aplikasi.

---

## 1. A01: Broken Access Control (Kontrol Akses Rusak)

Merupakan risiko keamanan web nomor satu di dunia. Terjadi ketika sistem gagal membatasi hak akses pengguna, sehingga pengguna dapat melihat atau memodifikasi data milik pengguna lain (IDOR: Insecure Direct Object References).

### Skenario Kerentanan:
Seorang user dengan ID `105` dapat melihat invoice user lain cukup dengan mengubah URL dari `/invoice/105` menjadi `/invoice/102`.

### Mitigasi Defensif (Laravel Policy / Gate):
Jangan pernah mengambil data langsung menggunakan ID tanpa memvalidasi kepemilikan data:

```php
// ANTI-PATTERN:
public function show($id) {
    return Invoice::findOrFail($id); // Siapa saja bisa memasukkan ID milik orang lain!
}

// POLA PERTAHANAN:
public function show($id) {
    $invoice = Invoice::findOrFail($id);
    
    // Otorisasi eksplisit menggunakan Policy
    $this->authorize('view', $invoice);
    
    return view('invoice.detail', compact('invoice'));
}
```

---

## 2. A02: Cryptographic Failures (Kegagalan Kriptografi)

Terjadi saat data sensitif (password, nomor rekening, token autentikasi) tidak dienkripsi dengan benar, disimpan dalam bentuk plain-text, atau ditransmisikan tanpa enkripsi HTTPS.

### Aturan Mitigasi:
1. **Hashing Password:** Wajib menggunakan algoritma *memory-hard* yang adaptif terhadap hardware GPU: **Argon2id** atau **Bcrypt** (cost factor minimal 12). Dilarang keras menggunakan MD5, SHA-1, atau SHA-256 untuk password.
2. **Enkripsi Data At-Rest:** Gunakan kunci simetris standar industri seperti **AES-256-GCM** atau **AES-256-CBC** melalui `Crypt::encryptString()` pada Laravel.
3. **Data In-Transit:** Terapkan HTTPS dengan TLS 1.3 dan aktifkan header `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

---

## 3. A03: Injection (Injeksi Kode & SQL)

Terjadi saat data yang dimasukkan oleh pengguna digabungkan langsung ke dalam perintah SQL, command sistem operasi, atau parser template tanpa validasi dan parameter binding.

### Mitigasi Defensif:
- **SQL Injection:** Gunakan PDO Prepared Statements atau ORM (Eloquent) dengan parameter binding. Hindari konkatenasi string SQL mentah.
- **OS Command Injection:** Hindari penggunaan fungsi `exec()`, `shell_exec()`, atau `system()`. Jika wajib menjalankan command eksternal, gunakan API terisolasi seperti Symfony Process component dengan argument array:
  ```php
  use Symfony\Component\Process\Process;
  $process = new Process(['git', 'status']);
  $process->run();
  ```

---

## 4. A04: Insecure Design (Desain Tidak Aman)

Kerentanan yang timbul akibat kegagalan arsitektur dan ketiadaan *Threat Modeling* sebelum kode ditulis, seperti ketiadaan pembatasan transaksi atau celah pada alur logika bisnis.

### Mitigasi Defensif:
- Terapkan **Rate Limiting** ketat pada endpoint sensitif (login, reset password, transaksi pembayaran, pengiriman OTP).
- Terapkan pola **State Machine** untuk alur transaksi (misal: pesanan tidak bisa berpindah dari `DIBATALKAN` langsung ke `SELESAI`).

---

## 5. A05: Security Misconfiguration (Miskonfigurasi Keamanan)

Miskonfigurasi pada server, framework, atau database, seperti membiarkan password default, mengaktifkan fitur debug di server publik, atau direktori listing terbuka.

### Mitigasi Defensif:
1. Pastikan `APP_DEBUG=false` di file `.env`.
2. Matikan directory listing di web server (`Options -Indexes` pada Apache).
3. Hapus file installer dan dokumentasi default (seperti `/phpinfo.php`, `test.php`).
4. Pasang header keamanan HTTP (`X-Frame-Options`, `X-Content-Type-Options`, `CSP`).

---

## 6. A06: Vulnerable and Outdated Components (Komponen Usang & Rentan)

Menggunakan package pihak ketiga (library Composer atau npm) yang telah memiliki CVE atau celah keamanan publik yang belum di-patch.

### Prosedur Audit Rutin:
Jalankan audit dependensi berkala di terminal:
```bash
# Audit package PHP (Composer)
composer audit

# Audit package JavaScript (Node.js)
npm audit
```
Segera lakukan update package jika terdeteksi kerentanan dengan tingkat keparahan HIGH atau CRITICAL.

---

## 7. A07: Identification and Authentication Failures (Kegagalan Autentikasi)

Kelemahan pada sistem login, sesi, atau reset password yang memungkinkan penyerang menebak password (*brute-force*), membajak sesi, atau melakukan *credential stuffing*.

### Mitigasi Defensif:
1. **Pencegahan Brute-Force:** Terapkan pembatasan percobaan login (maksimal 5 kali salah per 1 menit) menggunakan `RateLimiter::for('login', ...)` bawaan Laravel.
2. **Rotasi Session ID:** Regenerasi ID sesi setelah user berhasil login (`$request->session()->regenerate();`) untuk mencegah serangan *Session Fixation*.
3. **Kebijakan Password Kuat:** Wajibkan password minimal 8-12 karakter dengan kombinasi huruf besar, kecil, angka, dan simbol.

---

## 8. A08: Software and Data Integrity Failures (Kegagalan Integritas Data)

Aplikasi mengonsumsi library eksternal (CDN) atau payload serialisasi tanpa memvalidasi keutuhan dan keasliannya.

### Mitigasi Defensif:
1. **Subresource Integrity (SRI):** Saat memuat file JavaScript dari CDN publik (seperti cdnjs atau jsdelivr), selalu sertakan atribut integritas hash `integrity="sha384-..." crossorigin="anonymous"`.
2. **Hindari Insecure Deserialization:** Dilarang keras menggunakan fungsi bawaan PHP `unserialize()` pada input yang dikontrol pengguna; gunakan format `json_decode()` yang aman.

---

## 9. A09: Security Logging and Monitoring Failures (Kegagalan Logging & Monitoring)

Insiden keamanan atau aktivitas login mencurigakan tidak dicatat ke dalam log, sehingga serangan tidak terdeteksi hingga terjadi kebocoran data besar.

### Mitigasi Defensif:
1. Catat log setiap kejadian keamanan kritis:
   - Kegagalan login berulang kali dari IP yang sama.
   - Perubahan password dan perubahan role hak akses pengguna.
   - Upaya akses tidak sah ke endpoint privat (HTTP 403 Forbidden).
2. Jangan pernah mencatat data sensitif pengguna (password, CVV kartu kredit) ke dalam file log:
   ```php
   // Pada config/logging.php atau Controller:
   Log::warning('Percobaan login gagal untuk akun: ' . $request->input('email') . ' dari IP: ' . $request->ip());
   ```

---

## 10. A10: Server-Side Request Forgery (SSRF)

Terjadi saat aplikasi web mengambil resource dari URL yang diinput oleh pengguna tanpa memvalidasi apakah URL tersebut mengarah ke jaringan privat internal (seperti `127.0.0.1`, `localhost`, atau IP metadata cloud AWS/GCP `169.254.169.254`).

### Mitigasi Defensif:
Saat mengunduh konten dari URL yang dimasukkan user (misal fitur "Import Gambar dari URL"):
1. Validasi skema URL (hanya izinkan `http` atau `https`).
2. Saring dan blokir alamat IP privat dan loopback menggunakan filter `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`:
```php
$ip = gethostbyname(parse_url($url, PHP_URL_HOST));
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    throw new Exception('Akses ke jaringan privat internal ditolak.');
}
```
