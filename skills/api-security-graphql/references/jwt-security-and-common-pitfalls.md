# JSON Web Tokens (JWT) Security & Common Pitfalls

> Panduan audit arsitektur token JWT, analisis vektor serangan (`alg: none`, Key Confusion, weak HMAC), dan praktik terbaik implementasi refresh token.

---

## 1. Anatomi Token JWT & Vektor Serangan

```
  HEADER                      PAYLOAD                     SIGNATURE
[ eyJhbGci... ]      .      [ eyJzdWIi... ]      .      [ tjVA95Or... ]
       |                           |                           |
- alg: HS256 / RS256       - sub: 12345                - Hash HMAC / RSA
- typ: JWT                 - role: admin               - Melindungi integritas
                           - exp: 1712498200             Header & Payload
```

---

## 2. Vektor Serangan Kritis pada JWT

### A. Algoritma `none` (Bypass Verifikasi Tanda Tangan)
Beberapa parser JWT memperbolehkan header:
`{ "alg": "none", "typ": "JWT" }`
Jika server tidak menolak secara eksplisit, penyerang dapat memodifikasi payload (misal mengubah `role: "admin"`) dan menghapus bagian tanda tangan.

**Mitigasi**: Pastikan library JWT secara tegas menolak algoritma `none` dan mewajibkan algoritma tertentu (`algorithms=['RS256']`).

### B. Serangan Kebingungan Kunci (Key Confusion / Algorithm Switching)
Jika server menggunakan verifikasi asimetris (RS256) dengan public key RSA, namun library mengizinkan penyerang mengubah header menjadi `HS256`, server mungkin akan menggunakan public key RSA (yang dapat dibaca publik) sebagai secret key simetris HMAC.

**Mitigasi**: Kunci verifikasi tidak boleh dinamis berdasarkan header klien. Tentukan algoritma secara statis pada konfigurasi middleware.

---

## 3. Strategi Manajemen Token yang Aman

- [ ] **Masa Berlaku Pendek**: Access Token harus berumur pendek (5–15 menit).
- [ ] **Refresh Token Rotation**: Setiap kali refresh token digunakan, ganti dengan refresh token baru dan batalkan yang lama.
- [ ] **Penyimpanan di Frontend**: Gunakan cookie `HttpOnly; Secure; SameSite=Strict` untuk aplikasi web agar kebal dari pencurian via XSS.
- [ ] **Revocation List**: Sediakan mekanisme blacklist di Redis untuk mencabut token saat pengguna logout atau ganti password.
