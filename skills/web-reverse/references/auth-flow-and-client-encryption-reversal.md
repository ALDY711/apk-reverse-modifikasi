# Web Authentication Flow & Client-Side Encryption Reverse Engineering Guide

Panduan teknis komprehensif untuk menganalisis, memetakan, merekayasa balik (*reverse engineering*), dan mereproduksi alur autentikasi web modern (**Login**, **Register**, **Password Reset**) yang dilengkapi enkripsi sisi klien (*client-side encryption*), tanda tangan permintaan (*request signatures*), dan token anti-bot.

---

## 1. Arsitektur & Model Mental Autentikasi Web Modern

Aplikasi web modern (Single Page Applications, portal perbankan, e-commerce, dan sistem enterprise) jarang mengirimkan password dalam bentuk teks terbuka (*plaintext*) melalui HTTP POST. Alur data melewati beberapa lapisan transformasi sebelum menyentuh jaringan:

```
[Form Input: Email & Password]
             │
             ▼
[1. Pre-Flight Token Fetch] ──► Ambil Public Key RSA & Salt dinamis dari server
             │
             ▼
[2. Client-Side Encryption] ──► Password dienkripsi via JSEncrypt (RSA) / CryptoJS (AES)
             │
             ▼
[3. Anti-Bot / CAPTCHA Solv] ──► Token Turnstile / reCAPTCHA dieksekusi di background
             │
             ▼
[4. Request Signing] ──────────► Hitung X-Signature = HMAC(Payload + Timestamp + Nonce)
             │
             ▼
[5. Network Transport] ────────► POST /api/v1/auth/login (TLS + JA3/JA4 Fingerprint)
             │
             ▼
[6. Token & Session Issuance] ─► Server validasi & mengembalikan JWT / Set-Cookie Session
```

---

## 2. Taksonomi Enkripsi Sisi Klien (*Client-Side Crypto*)

### A. Asymmetric Encryption (RSA via JSEncrypt)
Banyak sistem enterprise mengambil kunci publik RSA dari server saat form dimuat, lalu mengenkripsi password dengan PKCS#1 v1.5 atau OAEP:
```javascript
// Pola Khas di Bundle JavaScript Frontend:
const encryptor = new JSEncrypt();
encryptor.setPublicKey(serverPublicKey);
const encryptedPassword = encryptor.encrypt(rawPassword);

const payload = {
  username: "user@example.com",
  password: encryptedPassword, // Menghasilkan base64 ciphertext RSA
  keyId: "key_2026_v1"
};
```
**Metodologi Reversal:**
1. Gunakan `auth_flow_tracer.py scan-js` untuk mendeteksi instansiasi `JSEncrypt` atau `setPublicKey`.
2. Pasang breakpoint di DevTools pada `encryptor.encrypt`.
3. Di Python, replikasikan enkripsi menggunakan pustaka `cryptography` atau `pycryptodome`:
   ```python
   from Crypto.PublicKey import RSA
   from Crypto.Cipher import PKCS1_v1_5
   import base64

   key = RSA.import_key(public_key_pem)
   cipher = PKCS1_v1_5.new(key)
   ciphertext = cipher.encrypt(raw_password.encode('utf-8'))
   encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
   ```

### B. Symmetric Encryption (AES via CryptoJS / WebCrypto)
Password atau seluruh payload form dienkripsi menggunakan AES-CBC atau AES-GCM dengan secret key statis atau diturunkan (*derived*) dari timestamp:
```javascript
// Pola CryptoJS AES:
const key = CryptoJS.enc.Utf8.parse("16_OR_32_BYTE_KEY");
const iv = CryptoJS.enc.Utf8.parse("16_BYTE_STATIC_IV");
const encrypted = CryptoJS.AES.encrypt(rawPassword, key, {
  iv: iv,
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7
}).toString();
```
**Metodologi Reversal:**
1. Cari keyword `CryptoJS.AES.encrypt` atau `window.crypto.subtle.encrypt`.
2. Periksa apakah `key` dan `iv` disimpan secara *hardcoded* di bundle JavaScript atau diekstraksi dari meta tag HTML (`<meta name="app-salt" content="...">`).
3. Replikasikan di Python dengan modul `Crypto.Cipher.AES`.

### C. Multi-Stage Hashing (Salt + Nonce + Timestamp)
Beberapa aplikasi web melakukan hashing lokal bertingkat untuk mencegah pengiriman password asli:
```javascript
const salt = response.data.salt; // dari endpoint pre-login
const stage1 = CryptoJS.SHA256(rawPassword).toString();
const stage2 = CryptoJS.MD5(stage1 + salt + timestamp).toString();
```

---

## 3. Dynamic Tracing & Interception via DevTools

Untuk menemukan fungsi enkripsi autentikasi secara cepat tanpa tersesat di puluhan ribu baris kode minified, terapkan teknik **Call Stack Interception**:

### Langkah 1: Hooking `fetch` dan `XMLHttpRequest`
Eksekusi hook berikut di Console Chrome DevTools sebelum menekan tombol Submit:
```javascript
(function() {
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
    if (url && (url.includes('login') || url.includes('auth') || url.includes('register'))) {
      console.group(`[AUTH TRACE] Fetch -> ${url}`);
      console.log('Payload:', args[1]?.body);
      console.log('Headers:', args[1]?.headers);
      console.trace('Call Stack');
      console.groupEnd();
    }
    return origFetch.apply(this, args);
  };
})();
```

### Langkah 2: Hooking Primitive Kriptografi
Pasang hook pada prototipe kriptografi umum untuk menangkap plaintext dan kunci:
```javascript
// Hook JSEncrypt jika digunakan
if (window.JSEncrypt) {
  const origEncrypt = window.JSEncrypt.prototype.encrypt;
  window.JSEncrypt.prototype.encrypt = function(string) {
    console.warn('[JSEncrypt Intercepted]');
    console.log('Plaintext Input :', string);
    console.log('Public Key Used :', this.getKey().getPublicKey());
    const res = origEncrypt.apply(this, arguments);
    console.log('Ciphertext Output:', res);
    return res;
  };
}

// Hook WebCrypto SubtleCrypto
if (window.crypto && window.crypto.subtle) {
  const origSubtle = window.crypto.subtle.encrypt;
  window.crypto.subtle.encrypt = function(algorithm, key, data) {
    console.warn('[WebCrypto Subtle.encrypt Intercepted]', algorithm, key);
    return origSubtle.apply(this, arguments);
  };
}
```

---

## 4. Analisis Token Keamanan: CSRF, Anti-Bot & JWT

### A. Siklus Token CSRF
- **Lokasi Ekstraksi**: Biasanya tersimpan di `<meta name="csrf-token" content="...">` atau cookie `XSRF-TOKEN`.
- **Injeksi Header**: Server mengharapkan header `X-CSRF-TOKEN` atau `X-XSRF-TOKEN` sama persis dengan cookie session.

### B. Cloudflare Turnstile & Google reCAPTCHA
- Pada alur register/login yang dilindungi Turnstile, form memuat iframe widget.
- Callback JavaScript `turnstile.render(container, { callback: (token) => ... })` menghasilkan token berumur pendek (~300 detik) yang dimasukkan ke payload:
  `cf_turnstile_response: "0.xxxx..."`.
- Dalam skenario audit atau rekayasa balik, gunakan solver terkelola atau browser automation dengan sidik jari tersamar (*stealth*).

### C. JSON Web Token (JWT) Audit & Inspection
Gunakan tool `auth_flow_tracer.py jwt-audit <TOKEN>` untuk mengevaluasi:
1. **Algoritma Header**: Apakah menggunakan `HS256`, `RS256`, atau `none` (vulnerable).
2. **Payload Claims**: Periksa kebocoran data sensitif (misal `role`, `is_admin`, `email`, password hash yang tidak sengaja dimasukkan).
3. **Masa Berlaku (`exp`)**: Validasi apakah token kedaluwarsa sesuai standar keamanan industri (15-60 menit untuk access token).

---

## 5. Blueprint Otomasi Replay Python (curl_cffi / JA3 Mimicking)

Ketika mereproduksi alur login/register dalam skrip pengujian backend atau security auditing, penggunaan `requests` standar sering diblokir oleh WAF karena TLS Fingerprint (JA3/JA4) yang tidak cocok dengan browser asli.

Gunakan `curl_cffi` dengan profil peniruan peramban:

```python
from curl_cffi import requests
import json
import time

def execute_auth_flow(base_url: str, username: str, encrypted_password: str) -> requests.Response:
    # Menggunakan sesi dengan peniruan peramban Chrome 124 JA3/JA4
    session = requests.Session(impersonate="chrome124")

    # 1. Ambil halaman awal untuk mendapatkan cookie session & CSRF
    resp_init = session.get(f"{base_url}/login")
    csrf_token = session.cookies.get("XSRF-TOKEN") or "EXTRACTED_FROM_HTML"

    # 2. Bangun payload & header otentikasi
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "X-CSRF-TOKEN": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": f"{base_url}/login",
    }

    payload = {
        "username": username,
        "password": encrypted_password,
        "remember": True,
        "timestamp": int(time.time()),
    }

    # 3. Kirim permintaan autentikasi
    response = session.post(
        f"{base_url}/api/v1/auth/login",
        json=payload,
        headers=headers,
    )

    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")
    return response
```

---

## 6. Ringkasan Toolkit Operasional

| Kebutuhan Analisis | Perintah / Alat | Output / Manfaat |
| :--- | :--- | :--- |
| **Pindai Enkripsi JS** | `python skills/web-reverse/scripts/auth_flow_tracer.py scan-js <app.js>` | Mendeteksi algoritma RSA, AES, SHA, header signature, dan parameter input. |
| **Audit Token JWT** | `python skills/web-reverse/scripts/auth_flow_tracer.py jwt-audit <token>` | Dekonstruksi header & claims, peringatan algoritma lemah/kadaluwarsa. |
| **Buat Replay Script** | `python skills/web-reverse/scripts/auth_flow_tracer.py gen-replay <URL>` | Template Python `curl_cffi` siap pakai dengan TLS browser impersonation. |
| **Hook DevTools Otomatis** | `python skills/web-reverse/scripts/devtools_hook_generator.py --mode fetch-xhr` | Script injeksi console untuk memetakan alur submit form secara instan. |
