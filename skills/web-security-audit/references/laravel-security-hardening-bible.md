# Laravel Security Hardening & Defensive Engineering Bible

Panduan komprehensif ini merangkum standar keamanan industri dan arsitektur defensif untuk aplikasi web berbasis framework **Laravel (v10 / v11)**, mencakup mitigasi OWASP Top 10, sanitasi database, proteksi sesi, keamanan template Blade, dan pengerasan konfigurasi server produksi.

---

## 1. Arsitektur Pertahanan Berlapis Laravel

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Alur Permintaan Masuk HTTP                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. LAYER WEB SERVER & NETWORK (Nginx / Cloudflare)                     │
│    ├── Enforce HTTPS & HSTS (Strict-Transport-Security)                │
│    ├── Blokir akses file sensitif: .env, .git, storage/logs            │
│    └── Terapkan Security Headers: CSP, X-Frame-Options, X-Content-Type │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. LAYER MIDDLEWARE GLOBAL (Kernel / bootstrap/app.php)                │
│    ├── TrustProxies (Mencegah pemalsuan Client IP / X-Forwarded-For)   │
│    ├── VerifyCsrfToken (Validasi token anti-CSRF pada POST/PUT/DELETE) │
│    ├── SecurityHeadersMiddleware (Injeksi header pertahanan HTTP)      │
│    └── ThrottleRequests (Rate limiting: 60 req/min)                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. LAYER OTORISASI & VALIDASI (FormRequest / Policies)                 │
│    ├── FormRequest Validation (Validasi tipe data, format, panjang)    │
│    └── Gate & Policy (Otorisasi granular: Role-Based Access Control)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. LAYER MODEL & DATABASE (Eloquent ORM)                               │
│    ├── Mass Assignment Defense ($fillable eksplisit, larang $guarded=[])│
│    └── PDO Parameterized Queries (Mencegah SQL Injection mentah)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. LAYER VIEW & OUTPUT (Blade Engine)                                  │
│    ├── Auto-Escape {{ $variable }} (htmlspecialchars otomatis)         │
│    └── Larang raw output {!! $data !!} untuk input user tanpa sanitasi │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Pencegahan Mass Assignment (Model Eloquent)

Mass Assignment terjadi ketika pengguna memasukkan parameter HTTP ekstra (misal `role=admin` atau `is_verified=1`) yang langsung dimasukkan ke model via `Model::create($request->all())`.

### Anti-Pattern Berbahaya:
```php
// SANGAT BERBAHAYA: Menonaktifkan proteksi mass assignment total
class User extends Authenticatable
{
    protected $guarded = []; // Penyerang bisa memanipulasi kolom 'role' atau 'balance'!
}
```

### Pola Pertahanan Standar:
Selalu definisikan array `$fillable` secara eksplisit hanya untuk kolom yang boleh diubah oleh user biasa:
```php
class User extends Authenticatable
{
    protected $fillable = [
        'name',
        'email',
        'phone',
        'address',
    ];

    // Kolom sensitif jangan pernah dimasukkan ke $fillable:
    // 'role', 'is_admin', 'email_verified_at', 'balance', 'password'
}
```

---

## 3. Pencegahan SQL Injection pada Eloquent & Raw Queries

Secara default, method Eloquent seperti `where()`, `find()`, dan `first()` menggunakan **PDO Parameter Binding** yang kebal terhadap SQL Injection. Kerentanan muncul saat developer menggunakan raw query expressions.

### Pola Rawan vs Pola Aman:

| Metode | Status Keamanan | Contoh Kode |
|---|---|---|
| `where('username', $input)` | **AMAN** (Prepared Statement) | `$user = User::where('username', $username)->first();` |
| `whereRaw("name = '$input'")` | **RAWAN SQLi** (Konkatenasi String) | `$user = User::whereRaw("name = '" . $name . "'")->first();` |
| `whereRaw("name = ?", [$input])` | **AMAN** (Parameter Binding) | `$user = User::whereRaw("name = ?", [$name])->first();` |
| `orderByRaw($sortBy)` | **RAWAN SQLi** (Identifier Injection) | `User::orderByRaw($request->get('sort'));` |

### Pengamanan `orderByRaw` Dinamis:
Jika kolom sorting dipilih oleh pengguna, selalu validasi terhadap whitelist kolom yang sah:
```php
$allowedColumns = ['name', 'created_at', 'price'];
$sortBy = in_array($request->get('sort'), $allowedColumns) ? $request->get('sort') : 'created_at';
$direction = strtolower($request->get('direction')) === 'desc' ? 'desc' : 'asc';

$products = Product::orderBy($sortBy, $direction)->paginate(15);
```

---

## 4. Keamanan Template Blade & Pencegahan XSS

### 1. Perbedaan Mendasar Sintaks Output
- **`{{ $variable }}` (Aman):** Laravel otomatis memanggil fungsi `htmlspecialchars($variable, ENT_QUOTES, 'UTF-8')`. Karakter berbahaya seperti `<script>` diubah menjadi `&lt;script&gt;`.
- **`{!! $variable !!}` (Raw / Tidak Di-escape):** Mengirimkan data mentah langsung ke browser. Jika variabel berasal dari input pengguna (misal nama produk, biodata, komentar), penyerang dapat menyisipkan payload Stored XSS.

### 2. Aturan Sanitasi Jika Wajib Menampilkan HTML (Rich Text Editor)
Jika aplikasi menggunakan editor WYSIWYG (Summernote, TinyMCE, CKEditor) dan harus menampilkan HTML:
Gunakan library pembersih HTML teruji seperti `mews/purifier` (HTMLPurifier):
```php
// Di Controller sebelum disimpan:
$cleanHtml = clean($request->input('deskripsi_produk'));
$product->description = $cleanHtml;

// Di Blade:
{!! clean($product->description) !!}
```

---

## 5. Proteksi CSRF (Cross-Site Request Forgery)

### 1. Form HTML Tradisional
Setiap form ber-method POST, PUT, atau DELETE wajib memuat token:
```html
<form method="POST" action="/lowongan/simpan">
    @csrf
    <!-- Token disisipkan otomatis sebagai input tersembunyi -->
    <input type="text" name="judul" required>
    <button type="submit">Kirim</button>
</form>
```

### 2. Request AJAX / Fetch / Axios
Pastikan meta tag CSRF tersedia di bagian `<head>`:
```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```
Dan konfigurasikan header AJAX secara global:
```javascript
// Konfigurasi Axios
axios.defaults.headers.common['X-CSRF-TOKEN'] = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// Konfigurasi Native Fetch
fetch('/api/update', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
    },
    body: JSON.stringify(payload)
});
```

---

## 6. Arsitektur Unggah File Aman (Secure File Upload)

Fitur upload file (misalnya dokumen lamaran CV, foto produk UMKM, bukti pembayaran) adalah salah satu target serangan paling berbahaya jika penyerang berhasil mengunggah file `.php` atau `.phtml`.

### 5 Aturan Wajib Upload File:
1. **Validasi MIME Type Asli (Bukan Sekadar Ekstensi):**
   ```php
   $request->validate([
       'dokumen_cv' => [
           'required',
           'file',
           'mimes:pdf,docx',        // Validasi ekstensi
           'mimetypes:application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document', // Validasi magic byte
           'max:5120',              // Batas maksimal 5MB
       ],
   ]);
   ```
2. **Ubah Nama File Secara Acak (UUID / Hash):**
   Jangan pernah menggunakan `$file->getClientOriginalName()` langsung sebagai nama file di disk:
   ```php
   // AMAN: Menggunakan hash otomatis bawaan Laravel
   $path = $request->file('dokumen_cv')->store('cv_uploads', 'private');
   ```
3. **Simpan di Luar Direktori `public`:**
   Simpan file sensitif di disk `storage/app/private/` bukan di `public/uploads/`.
4. **Matikan Eksekusi PHP di Direktori Upload (Nginx):**
   ```nginx
   location ^~ /storage/ {
       # Matikan eksekusi script PHP di direktori publik
       location ~ \.php$ {
           deny all;
       }
   }
   ```

---

## 7. Pengerasan Konfigurasi Produksi (`.env` & `config/`)

Sebelum sistem diakses publik di server produksi:

```ini
# 1. Matikan Mode Debug
APP_ENV=production
APP_DEBUG=false

# 2. Pastikan Kunci Enkripsi Terisi
APP_KEY=base64:Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=

# 3. Paksa Sesi Cookie Menggunakan HTTPS
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
SESSION_LIFETIME=120
```

### Jalankan Optimasi Cache Laravel di Server Produksi:
```bash
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan event:cache
```
Perintah ini membekukan konfigurasi ke dalam file cache tunggal dan mencegah pembacaan dinamis file `.env` pada setiap request.
