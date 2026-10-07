# Subdomain Takeover, DNS Security, and Surface Hygiene

> Panduan komprehensif audit keamanan DNS, deteksi *Dangling CNAME records*, pencegahan pengambilalihan subdomain (*Subdomain Takeover* — OWASP A05:2021), serta standarisasi record email & sertifikat (SPF, DKIM, DMARC, CAA, DNSSEC).

---

## 1. Anatomi Subdomain Takeover (Dangling CNAMEs)

Subdomain Takeover terjadi ketika rekaman DNS (khususnya tipe `CNAME`) sebuah organisasi mengarah ke layanan pihak ketiga atau *cloud provider* (misalnya AWS S3 bucket, GitHub Pages, Heroku app, atau Azure web app) yang **sumber dayanya telah dihapus**, namun rekaman DNS-nya **lupa dibersihkan**:

```
+-----------------------------------------------------------------------------------+
| 1. REKAMAN DNS ORGANISASI                                                         |
|    docs.perusahaan.com  IN CNAME  perusahaan-docs.s3-website-us-east-1.amazonaws.com |
+-----------------------------------------------------------------------------------+
                                          |
                                          v  (Developer menghapus S3 Bucket karena proyek selesai)
+-----------------------------------------------------------------------------------+
| 2. KONDISI DANGLING POINTER                                                       |
|    Rekaman DNS masih aktif, tetapi bucket "perusahaan-docs" sudah TIDAK ADA di S3!|
+-----------------------------------------------------------------------------------+
                                          |
                                          v  (Penyerang menemukan celah ini)
+-----------------------------------------------------------------------------------+
| 3. PENGAMBILALIHAN OLEH PENYERANG                                                 |
|    Penyerang mendaftarkan bucket baru di AWS S3 dengan nama "perusahaan-docs"!     |
|    Hasil: docs.perusahaan.com kini menyajikan konten milik penyerang!             |
+-----------------------------------------------------------------------------------+
```

### Dampak Keamanan Pengambilalihan Subdomain:
* **Pencurian Cookie Sesi:** Jika cookie disetel dengan cakupan wildcard (`domain=.perusahaan.com`), penyerang di `docs.perusahaan.com` dapat membaca cookie sesi pengguna aplikasi utama.
* **Bypass Kebijakan CORS / CSP:** Subdomain tepercaya sering masuk *whitelist* pada header CSP `script-src` atau `connect-src`.
* **Phishing Kredensial Kredibel:** Menyajikan form login palsu di bawah domain resmi perusahaan dengan sertifikat TLS yang sah.

---

## 2. Katalog Sidik Jari (Fingerprints) Layanan Cloud Rentan

Jika subdomain mengembalikan salah satu pesan error spesifik berikut, layanan tersebut rentan diambil alih:

| Layanan Cloud / SaaS | Pola CNAME Target | Sidik Jari Error (Response Body Fingerprint) |
|---|---|---|
| **AWS S3** | `*.s3.amazonaws.com`<br>`*.s3-website-*.amazonaws.com` | `The specified bucket does not exist`<br>`NoSuchBucket` |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here.` |
| **Heroku** | `*.herokuapp.com` | `No such app`<br>`Heroku | No such app` |
| **Microsoft Azure** | `*.azurewebsites.net`<br>`*.cloudapp.net` | `404 Web Site not found.` |
| **Cloudflare** | `*.cdn.cloudflare.net` | `Error 1016: Origin DNS error` |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain:` |
| **Pantheon** | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek.` |
| **Tumblr** | `*.tumblr.com` | `Whatever you were looking for doesn't exist` |

---

## 3. Audit Standarisasi Keamanan DNS

Selain CNAME, postur keamanan domain harus mencakup rekaman validasi email dan penerbitan sertifikat:

### A. DMARC (Domain-based Message Authentication, Reporting, and Conformance)
Rekaman TXT pada `_dmarc.domain.com`:
```dns
_dmarc.domain.com.  IN TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@domain.com;"
```
* **Kebijakan `p=none`:** Hanya memantau, tidak mencegah spoofing email.
* **Kebijakan `p=quarantine`:** Mengirim email yang gagal verifikasi ke folder spam.
* **Kebijakan `p=reject` (Standar Tertinggi):** Menolak email yang gagal SPF/DKIM sepenuhnya di level server penerima.

### B. SPF (Sender Policy Framework)
Rekaman TXT pada apex domain:
```dns
domain.com.  IN TXT  "v=spf1 include:_spf.google.com -all"
```
* Selalu gunakan akhiran hard-fail **`-all`**, bukan soft-fail `~all` atau `?all`.

### C. CAA (Certification Authority Authorization)
Membatasi Otoritas Sertifikat (CA) mana saja yang diizinkan menerbitkan sertifikat TLS/SSL untuk domain Anda (mencegah penerbitan sertifikat liar dari CA pihak ketiga):
```dns
domain.com.  IN CAA  0 issue "letsencrypt.org"
domain.com.  IN CAA  0 issue "digicert.com"
domain.com.  IN CAA  0 iodef "mailto:security@domain.com"
```

---

## 4. Alur Kerja Remediasi Defensif

1. **Pemetaan Siklus Hidup Aset Cloud:**
   * Terapkan kebijakan CI/CD: Sebelum *bucket*, *app instance*, atau *CDN distribution* dihapus, skrip dekomisioning wajib menghapus rekaman CNAME terkait di DNS provider (Route 53, Cloudflare, BIND) terlebih dahulu.
2. **Klaim Domain Khusus (Domain Verification):**
   * Gunakan penyedia SaaS yang mewajibkan verifikasi kepemilikan domain via rekaman DNS TXT unik sebelum CNAME dapat diarahkan (misalnya fitur *Custom Domain Verification* pada GitHub Enterprise atau AWS CloudFront).
3. **Audit Otomatis Terjadwal:**
   * Jalankan skrip `subdomain_takeover_audit.py` secara berkala (misalnya setiap minggu melalui cron job) untuk memindai seluruh subdomain organisasi terhadap rekaman menggantung.
