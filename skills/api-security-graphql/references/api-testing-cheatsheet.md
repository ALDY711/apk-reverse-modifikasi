# Modern API & GraphQL Security Testing Cheatsheet

> Rangkuman cepat perintah testing cURL, header HTTP keamanan API, dan daftar uji verifikasi IDOR / BOLA.

---

## 1. Perintah Audit Cepat via cURL

### Pengujian Introspeksi GraphQL:
```bash
# Uji apakah kueri introspeksi aktif di endpoint GraphQL:
curl -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### Pengujian Bypass Metode HTTP pada REST:
```bash
# Uji HTTP Verb Tampering jika POST /users diblokir:
curl -X HEAD https://api.example.com/api/users
curl -X PUT -H "X-HTTP-Method-Override: PATCH" https://api.example.com/api/users/1
```

### Pengujian IDOR / BOLA:
```bash
# 1. Login sebagai User A (dapatkan Token A)
# 2. Login sebagai User B (dapatkan Token B dan Resource ID B, misal invoice 2005)
# 3. Lakukan request menggunakan Token A tetapi menargetkan Resource ID B:
curl -X GET https://api.example.com/api/invoices/2005 \
  -H "Authorization: Bearer <TOKEN_USER_A>"
```
*Jika respon menghasilkan status 200 OK dengan data User B, maka endpoint terbukti rentan BOLA!*

---

## 2. Checklist Header Keamanan API

| Header | Nilai yang Direkomendasikan | Fungsi |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Mencegah framing API dan injeksi skrip. |
| `X-Content-Type-Options` | `nosniff` | Mencegah MIME sniffing response payload. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Memaksa koneksi HTTPS secara permanen. |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Mencegah caching data sensitif di proxy / browser. |
| `Access-Control-Allow-Origin` | Domain whitelist spesifik (bukan `*`) | Mengamankan pembagian resource antar-origin. |
