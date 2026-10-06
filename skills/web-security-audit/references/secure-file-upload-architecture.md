# Secure File Upload Architecture & Defensive Engineering Manual

Panduan teknis defensif komprehensif untuk mencegah kerentanan Unrestricted File Upload (CWE-434), eksekusi kode berbahaya jarak jauh (Remote Code Execution / RCE via Web Shell), Stored Cross-Site Scripting (XSS via SVG/HTML), Path Traversal dalam nama file, serta serangan Denial of Service berbasis kompresi (ZIP/Decompression Bomb).

---

## 1. VEKTOR SERANGAN FILE UPLOAD & DAMPAK RISIKO

File upload adalah salah satu permukaan serangan paling berisiko tinggi pada aplikasi web jika tidak diisolasi dengan benar:

| Vektor Serangan | Mekanisme Eksploitasi | Dampak |
|---|---|---|
| **Eksekusi Web Shell (RCE)** | Penyerang mengunggah file berekstensi `.php`, `.phtml`, `.phar`, `.jsp`, atau `.py` ke folder publik web root, lalu memanggil URL file tersebut secara langsung via browser untuk mengeksekusi shell server. | **Full Server Compromise** — Penyerang dapat membaca file konfigurasi, database, dan mengontrol server. |
| **Bypass Ekstensi Ganda & Null-Byte** | Penyerang menggunakan trik nama file seperti `shell.php.jpg`, `shell.pHp`, `shell.php%00.png`, atau `shell.php;.jpg` untuk mengelabui filter ekstensi sederhana. | Melewati validasi backend sederhana dan tetap dieksekusi sebagai script pada web server yang miskonfigurasi. |
| **Polyglot File Attack** | Penyerang menyisipkan kode PHP atau JavaScript berbahaya di dalam komentar atau EXIF data file gambar valid (JPEG/GIF). Gambar tetap valid di mata parser gambar sederhana, namun dapat dieksekusi jika server menjalankan LFI (Local File Inclusion). | Eksekusi kode melalui kombinasi LFI atau parser server yang tidak ketat. |
| **Stored XSS via SVG / HTML** | Penyerang mengunggah gambar berformat `.svg` atau file `.html` yang memuat script berbahaya (`<svg onload="alert(document.cookie)">`). Saat pengguna lain atau admin membuka link gambar, script dieksekusi dalam konteks origin domain target. | Pencurian sesi admin, pembajakan akun, defacement. |
| **Path Traversal / Arbitrary Overwrite** | Penyerang mengirimkan nama file dengan direktori traversal: `../../../../var/www/html/index.php`. | Menimpa file sistem atau kode inti aplikasi web yang menyebabkan downtime atau backdooring. |
| **Pixel Flood / Decompression Bomb (DoS)** | Penyerang mengunggah file gambar dengan dimensi kanvas raksasa (misal: 100.000 x 100.000 piksel terkompresi menjadi beberapa kilobyte) atau file ZIP terkompresi tinggi. Saat server merender ulang atau mengekstraknya di memori, server kehabisan RAM (*Out of Memory / OOM crash*). | Server hang, kernel crash, Denial of Service. |

---

## 2. ARSITEKTUR PERTAHANAN MULTI-LAPIS (DEFENSE-IN-DEPTH)

Sistem penerimaan file harus menerapkan **5 Lapisan Pertahanan Absolut**:

```
[ User Upload Request ]
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ LAPISAN 1: Sanitasi Nama File & Penghapusan Ekstensi Asli   │
│ - Buang nama file asli sepenuhnya                            │
│ - Generate nama file acak kriptografis (UUID v4)            │
│ - Normalisasi dan paksa huruf kecil ekstensi                │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ LAPISAN 2: Validasi Tipe Konten & Magic Bytes               │
│ - Whitelist ketat ekstensi yang diizinkan (hanya jpg, png)  │
│ - Verifikasi Magic Bytes biner asli (libmagic / finfo)      │
│ - Tolak jika MIME byte tidak cocok dengan ekstensi         │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ LAPISAN 3: Re-encoding & Sanitasi Gambar (Strip Polyglot)   │
│ - Baca ulang kanvas gambar menggunakan engine GD / Imagick  │
│ - Render ulang file baru (menghancurkan semua EXIF/payload) │
│ - Khusus SVG: wajib dibersihkan dengan XML Sanitizer        │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ LAPISAN 4: Isolasi Penyimpanan (Storage Isolation)          │
│ - Simpan di luar direktori publik web root (Non-Web Accessible)│
│ - Atau simpan di Object Storage terisolasi (AWS S3 / GCP)  │
│ - Matikan eksekusi script pada folder penyimpanan           │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ LAPISAN 5: Header Pengiriman Respons yang Aman             │
│ - Force download: `Content-Disposition: attachment`         │
│ - Header anti-sniffing: `X-Content-Type-Options: nosniff`    │
│ - CSP: batasi eksekusi objek dan script                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. IMPLEMENTASI KODE DEFENSIVE (PHP / LARAVEL)

### 3.1. Validasi Magic Bytes & FormRequest Sanitized

Jangan pernah mengandalkan `$file->getClientOriginalExtension()` atau `$file->getClientMimeType()`, karena kedua nilai tersebut dikirimkan langsung oleh klien (dapat dimanipulasi dengan Burp Suite).

```php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\File;

class SecureAvatarUploadRequest extends FormRequest
{
    public function authorize(): bool
    {
        return auth()->check();
    }

    public function rules(): array
    {
        return [
            'avatar' => [
                'required',
                // Validasi ketat ukuran dan tipe file
                File::image()
                    ->min('1kb')
                    ->max('2mb')
                    ->dimensions(File::image()->maxWidth(2000)->maxHeight(2000)),
                // Batasi ekstensi hanya format gambar aman
                'mimes:jpeg,jpg,png,webp',
            ],
        ];
    }
}
```

### 3.2. Rekonstruksi Ulang Gambar (Re-Encoding) untuk Menghancurkan Polyglot Shell

Dengan merender ulang gambar dari nol ke dalam kanvas baru, semua payload tersembunyi yang diselipkan pada komentar metadata EXIF atau slack space biner akan terhapus total.

```php
namespace App\Services;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;
use RuntimeException;

class SecureImageProcessor
{
    private const ALLOWED_MIME_TYPES = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
    ];

    public function processAndStore(UploadedFile $file, string $disk = 'private_uploads'): string
    {
        // 1. Validasi Magic Bytes menggunakan Fileinfo asli server
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $realMime = $finfo->file($file->getRealPath());

        if (!array_key_exists($realMime, self::ALLOWED_MIME_TYPES)) {
            throw new RuntimeException("Tipe konten biner tidak diizinkan: {$realMime}");
        }

        $safeExtension = self::ALLOWED_MIME_TYPES[$realMime];

        // 2. Re-encode menggunakan GD (Memusnahkan semua payload EXIF/PHP Polyglot)
        $sourceImage = match ($realMime) {
            'image/jpeg' => @imagecreatefromjpeg($file->getRealPath()),
            'image/png'  => @imagecreatefrompng($file->getRealPath()),
            'image/webp' => @imagecreatefromwebp($file->getRealPath()),
            default      => false,
        };

        if (!$sourceImage) {
            throw new RuntimeException("File gambar rusak atau memuat struktur biner tidak valid.");
        }

        // 3. Buat nama file acak kriptografis baru (UUID v4)
        $randomFilename = Str::uuid()->toString() . '.' . $safeExtension;
        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $randomFilename;

        // 4. Tulis ulang file gambar murni tanpa metadata
        $saved = match ($realMime) {
            'image/jpeg' => imagejpeg($sourceImage, $tempPath, 85),
            'image/png'  => imagepng($sourceImage, $tempPath, 8),
            'image/webp' => imagewebp($sourceImage, $tempPath, 85),
        };

        imagedestroy($sourceImage);

        if (!$saved) {
            @unlink($tempPath);
            throw new RuntimeException("Gagal melakukan serialisasi ulang gambar.");
        }

        // 5. Simpan file yang telah disanitasi ke storage terisolasi
        $storagePath = 'avatars/' . $randomFilename;
        Storage::disk($disk)->put($storagePath, file_get_contents($tempPath));

        // Hapus file sementara
        @unlink($tempPath);

        return $storagePath;
    }
}
```

---

## 4. PENANGANAN AMAN FORMAT SVG (ANTI STORED-XSS)

File SVG (`Scalable Vector Graphics`) berbasis XML dan secara native dapat mengeksekusi script JavaScript:

```xml
<!-- CONTOH SVG JAHAT (STORED XSS) -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS!')">
  <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
  <script type="text/javascript">
    fetch('/api/admin/steal-token?cookie=' + encodeURIComponent(document.cookie));
  </script>
</svg>
```

### Aturan Emas untuk File SVG:
1. **Rekomendasi Utama:** Jangan izinkan upload SVG dari pengguna umum jika tidak mutlak diperlukan.
2. **Jika Wajib Mendukung SVG:** Gunakan parser sanitasi XML ketat seperti `enshrined/svg-sanitize` untuk melucuti semua tag `<script>`, atribut event listener (`onload`, `onerror`, `onclick`), serta atribut link berbahaya (`xlink:href="javascript:..."`).
3. **Penyajian Respons:** Jika menyajikan SVG kepada pengguna, wajib sertakan header:
   ```http
   Content-Type: image/svg+xml
   Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
   X-Content-Type-Options: nosniff
   ```

---

## 5. KONFIGURASI WEB SERVER (MEMBLOKIR EKSEKUSI DI FOLDER UPLOAD)

Bahkan jika ada file PHP atau script berbahaya yang berhasil tersimpan di server, pastikan web server **menolak keras untuk mengeksekusinya**.

### 5.1. Konfigurasi Nginx (Blokir PHP di Folder Upload)

Tambahkan blok berikut pada konfigurasi virtual host Nginx:

```nginx
# Mencegah eksekusi script apa pun di dalam folder upload publik
location ^~ /storage/uploads/ {
    # Larang akses file yang memiliki ekstensi executable
    location ~* \.(php|phtml|phar|pl|py|jsp|asp|sh|cgi|bash)$ {
        deny all;
        return 404;
    }
    
    # Nonaktifkan fastcgi pass di folder ini
    fastcgi_intercept_errors off;
    
    # Paksa header nosniff
    add_header X-Content-Type-Options "nosniff" always;
}
```

### 5.2. Konfigurasi Apache (`.htaccess` di Folder Upload)

Letakkan file `.htaccess` di dalam direktori penyimpanan upload:

```apache
# Matikan interpreter PHP di direktori ini
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php8.c>
    php_flag engine off
</IfModule>

# Paksa semua file diperlakukan sebagai static stream murni
SetHandler default-handler

# Tolak akses ke semua file dengan ekstensi executable
<FilesMatch "\.(?i:php|phtml|phar|pl|py|jsp|asp|sh|cgi)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

# Header nosniff
Header set X-Content-Type-Options "nosniff"
```

---

## 6. PENCEGAHAN PATH TRAVERSAL PADA FILENAME

Jangan pernah menggunakan nama file yang dikirimkan oleh klien secara langsung dalam fungsi penyimpanan seperti `file_put_contents()` atau `move_uploaded_file()`.

```php
// CONTOH RENTAN (Path Traversal)
$filename = $_FILES['avatar']['name']; // Bisa bernilai: "../../../../var/www/html/shell.php"
move_uploaded_file($_FILES['avatar']['tmp_name'], "/var/www/uploads/" . $filename);

// CONTOH AMAN
// 1. Buang semua path separator dan komponen berbahaya
$safeBasename = basename($_FILES['avatar']['name']);
$cleanFilename = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $safeBasename);

// 2. ATAU LEBIH BAIK: Abaikan nama asli, generate ID unik murni
$isolatedFilename = bin2hex(random_bytes(16)) . '.' . $validatedExtension;
```
