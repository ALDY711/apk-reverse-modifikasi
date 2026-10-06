# Database & ORM Hardening, SQLi Defense, and Mass Assignment Manual

Panduan teknis mendalam untuk mencegah serangan **SQL Injection (In-band, Blind, Time-based, Second-Order)** pada layer Object-Relational Mapping (ORM) seperti Laravel Eloquent, Node.js Prisma/TypeORM, dan PDO, serta mitigasi celah **Mass Assignment** dan hardening konfigurasi server database MySQL/PostgreSQL.

---

## 1. ANATOMI KERENTANAN SQL INJECTION (SQLi)

SQL Injection terjadi ketika input data yang tidak dipercaya digabungkan langsung (*string concatenation*) ke dalam query SQL tanpa parameter binding atau prepared statement.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TAKSONOMI SERANGAN SQLi                         │
├───────────────────┬────────────────────────────────────────────────────┤
│ In-Band SQLi      │ Penyerang mengekstraksi data langsung dari respons │
│ (Error/UNION)     │ HTTP menggunakan pesan error atau clause UNION ALL.│
├───────────────────┼────────────────────────────────────────────────────┤
│ Inferential SQLi  │ Server tidak menampilkan error atau output query:  │
│ (Blind Boolean)   │ Penyerang menebak data karakter demi karakter      │
│                   │ berdasarkan respons TRUE vs FALSE (HTTP 200 vs 500)│
├───────────────────┼────────────────────────────────────────────────────┤
│ Inferential SQLi  │ Penyerang menggunakan fungsi sleep database:       │
│ (Blind Time-based)│ `SLEEP(5)` atau `pg_sleep(5)` untuk mengonfirmasi  │
│                   │ kebenaran tebakan karakter berdasarkan latensi.    │
├───────────────────┼────────────────────────────────────────────────────┤
│ Second-Order SQLi │ Payload tersimpan aman di database saat input awal,│
│ (Stored SQLi)     │ namun dieksekusi sebagai query dinamis di fungsi   │
│                   │ sekunder (misal: saat proses generate invoice/cron)│
└───────────────────┴────────────────────────────────────────────────────┘
```

---

## 2. TITIK LEMAH RAW QUERY PADA ORM (LARAVEL ELOQUENT)

Meskipun Eloquent ORM secara default menggunakan PDO Prepared Statements untuk method standar (`where()`, `find()`, `create()`), penggunaan method **Raw Query** tanpa parameter binding membuka celah SQLi fatal.

### 2.1. Katalog Anti-Pattern (Kode Berbahaya) vs Remediasi

#### Kasus A: `whereRaw()` dengan String Interpolation
```php
// SANGAT BAHAYA (SQL Injection Langsung)
$username = $request->input('user');
$users = DB::table('users')->whereRaw("username = '$username'")->get();

// PERBAIKAN: Gunakan Parameter Binding PDO
$users = DB::table('users')
    ->whereRaw('username = ?', [$username])
    ->get();
```

#### Kasus B: `orderByRaw()` dengan Input Klien
Penyerang sering memanipulasi parameter pengurutan tabel (`?sort=price; SELECT SLEEP(5);--`):
```php
// SANGAT BAHAYA (Bypasses Prepared Statement pada clause ORDER BY)
$sortBy = $request->input('sort', 'created_at');
$direction = $request->input('dir', 'desc');
$products = Product::orderByRaw("$sortBy $direction")->get();

// PERBAIKAN: Whitelist Kolom dan Arah Pengurutan
$allowedColumns = ['created_at', 'price', 'name', 'stock'];
$allowedDirections = ['asc', 'desc'];

$sortBy = in_array(strtolower($sortBy), $allowedColumns, true) ? strtolower($sortBy) : 'created_at';
$direction = in_array(strtolower($direction), $allowedDirections, true) ? strtolower($direction) : 'desc';

$products = Product::orderBy($sortBy, $direction)->get();
```

#### Kasus C: `havingRaw()` dan `groupByRaw()`
```php
// SANGAT BAHAYA
$minTotal = $request->input('min');
$orders = Order::havingRaw("total > $minTotal")->get();

// PERBAIKAN: Binding Tipe Data Integer atau Placeholder
$orders = Order::havingRaw('total > ?', [(int) $minTotal])->get();
```

---

## 3. MITIGASI MASS ASSIGNMENT VULNERABILITY

Mass Assignment terjadi ketika framework secara otomatis memetakan seluruh payload request HTTP ke dalam atribut model database tanpa penyaringan:

```php
// CONTOH KRITIS: Penyerang mengirimkan JSON: {"name": "Budi", "is_admin": true, "role": "superadmin"}
User::create($request->all()); // Akun baru otomatis menjadi superadmin!
```

### 3.1. Larangan Anti-Pattern `$guarded = []`
Banyak developer menonaktifkan proteksi Mass Assignment demi kemudahan:
```php
class User extends Model
{
    protected $guarded = []; // DILARANG KERAS DI PRODUKSI!
}
```

### 3.2. Pola Pertahanan Whitelist `$fillable` & FormRequest

```php
// 1. Deklarasikan hanya kolom yang aman untuk diisi pengguna
class User extends Model
{
    protected $fillable = [
        'name',
        'email',
        'password',
        'phone_number',
        // Kolom sensitif seperti 'role', 'is_admin', 'email_verified_at', 'balance' JANGAN dimasukkan!
    ];
}

// 2. Selalu gunakan FormRequest dengan validasi ketat
public function register(RegisterUserRequest $request)
{
    // Hanya mengambil data yang lolos validasi FormRequest
    $validatedData = $request->validated();
    
    $user = User::create([
        'name'     => $validatedData['name'],
        'email'    => $validatedData['email'],
        'password' => Hash::make($validatedData['password']),
    ]);
    
    return response()->json($user, 201);
}
```

---

## 4. HARDENING SERVER DATABASE (MYSQL / MARIADB / POSTGRESQL)

Keamanan aplikasi tidak lengkap tanpa pengerasan pada layer server database itu sendiri.

### 4.1. Prinsip Hak Akses Minimal (Principle of Least Privilege)
Jangan pernah menghubungkan aplikasi web menggunakan akun `root` atau `postgres` superuser.

```sql
-- Buat user khusus aplikasi dengan hak terbatas hanya untuk DML (Data Manipulation)
CREATE USER 'app_user'@'127.0.0.1' IDENTIFIED BY 'K4t4_Sand1_Kript0gr4f1s_Ku4t!';

-- Berikan izin hanya untuk operasi yang diperlukan oleh aplikasi web sehari-hari
GRANT SELECT, INSERT, UPDATE, DELETE ON `nama_database`.* TO 'app_user'@'127.0.0.1';

-- JANGAN PERNAH memberikan izin berikut pada user aplikasi web:
-- REVOKE DROP, ALTER, CREATE, GRANT OPTION, SUPER, FILE, PROCESS ON *.* FROM 'app_user'@'127.0.0.1';

FLUSH PRIVILEGES;
```

### 4.2. Matikan `LOAD DATA LOCAL INFILE`
Fitur `LOAD DATA LOCAL INFILE` di MySQL dapat dieksploitasi dalam skenario server rogue atau SQLi untuk membaca file lokal server web (misal `/etc/passwd` atau `.env`):

Tambahkan di `/etc/mysql/my.cnf` atau `my.ini`:
```ini
[mysqld]
local_infile=0

[mysql]
local_infile=0
```

### 4.3. Konfigurasi Koneksi Database Terenkripsi (TLS / SSL)
Pastikan lalu lintas query antara web server dan database server terenkripsi:

```env
# Konfigurasi di .env Laravel
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app_user
DB_PASSWORD=secret
MYSQL_ATTR_SSL_CA=/path/to/ca-cert.pem
MYSQL_ATTR_SSL_VERIFY_SERVER_CERT=true
```

---

## 5. CHECKLIST AUDIT KEAMANAN DATABASE

- [ ] Tidak ada penggunaan `DB::raw()`, `whereRaw()`, atau `orderByRaw()` dengan penggabungan string variabel (`$var`).
- [ ] Semua model Eloquent menggunakan whitelist `$fillable` yang ketat (tidak ada `protected $guarded = []`).
- [ ] User database aplikasi tidak memiliki hak `DROP`, `ALTER`, `FILE`, atau `SUPER`.
- [ ] `local_infile` bernilai `0` (nonaktif).
- [ ] Database tidak membuka port publik `3306`/`5432` ke internet luas (hanya `bind-address = 127.0.0.1` atau private VPC subnet).
- [ ] Koneksi menggunakan SSL/TLS sertifikat terverifikasi jika database berada di host terpisah.
