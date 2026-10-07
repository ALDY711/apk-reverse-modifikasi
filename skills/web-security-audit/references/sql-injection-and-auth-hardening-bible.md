# SQL Injection & Authentication Hardening Bible (Login & Register Security)

Buku panduan teknis mendalam mengenai analisis kelemahan, audit statis/dinamis, dan pengerasan sistem keamanan (*hardening*) basis data SQL pada alur autentikasi web (**Login**, **Registrasi Pengguna**, dan **Manajemen Kredensial**).

---

## 1. Taksonomi Kelemahan SQL pada Alur Autentikasi

Autentikasi adalah pintu gerbang utama aplikasi. Celah SQL Injection pada endpoint login dan registrasi memiliki dampak paling destruktif, mulai dari pengambilalihan akun (*account takeover*), *privilege escalation* menjadi administrator, hingga kompromi penuh basis data.

```
                              [Form Autentikasi]
                                ┌───────┴───────┐
                                ▼               ▼
                            [Login]        [Register]
                                │               │
          ┌─────────────────────┴───────┐       │
          ▼                             ▼       ▼
[Classic Auth Bypass]          [Blind Timing]  [Second-Order SQLi]
(Konkatenasi String ' OR 1=1)  (Subquery Ekstraksi) (Payload Tersimpan)
                                                        │
                                                        ▼
                                                [Eksekusi di Sesi Lain /
                                                 Query Profil Selanjutnya]
```

---

### A. Classic Authentication Bypass
Terjadi ketika aplikasi menyusun query login dengan menggabungkan string input pengguna secara langsung tanpa parameter binding.

**Pola Rentan (PHP):**
```php
// RENTAN TERHADAP INJEKSI SQL
$user = $_POST['username'];
$pass = $_POST['password'];
$sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
$result = $db->query($sql);

if ($result->num_rows > 0) {
    // Login berhasil!
}
```
**Mekanisme Kerentanan:**
Jika penyerang memasukkan `admin' --` atau `' OR 1=1 --`, query yang terbentuk menjadi:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
```
Klausa pengecekan password diabaikan sebagai komentar SQL, memberikan akses seketika ke akun target.

---

### B. Second-Order SQL Injection (Jalur Registrasi $\rightarrow$ Profil/Login)
Banyak pengembang menganggap aman karena formulir registrasi memakai prepared statement atau fungsi escaping dasar (`addslashes`). Namun, bahaya muncul ketika data yang disimpan di database ditarik kembali dan disisipkan ke query kedua secara dinamis.

**Skenario Serangan:**
1. Penyerang mendaftar akun baru dengan username berbahaya: `admin' --`.
2. Data tersimpan di tabel `users` (lolos tanpa eksekusi langsung).
3. Saat pengguna login atau membuka profil, aplikasi menjalankan query kedua:
   ```php
   // Controller Catatan Aktivitas / Profil:
   $current_user = $_SESSION['username']; // Bernilai: admin' --
   $sql = "UPDATE logs SET last_login = NOW() WHERE username = '$current_user'";
   $db->query($sql); // EKSPLOITASI TERJADI DI SINI!
   ```

---

### C. Blind SQL Injection (Boolean & Time-Based)
Jika otentikasi tidak menampilkan pesan error basis data, penyerang dapat mengekstraksi data bit-demi-bit melalui respon bersyarat (*conditional delay*):
```sql
admin' AND (SELECT IF(ASCII(SUBSTRING(password_hash, 1, 1)) = 97, SLEEP(3), 0) FROM users WHERE username = 'admin') --
```
Jika respons tertunda 3 detik, karakter pertama hash adalah huruf 'a' (ASCII 97).

---

## 2. Audit & Standarisasi Penyimpanan Kata Sandi (Password Hashing)

Kegagalan fatal kedua pada modul login/register adalah cara kata sandi disimpan di tabel basis data.

### Matriks Evaluasi Algoritma Hash:

| Algoritma | Status Keamanan | Kecepatan Komputasi | Rekomendasi Tindakan |
| :--- | :--- | :--- | :--- |
| **MD5** | ❌ Kritis / Tidak Aman | Sangat Cepat ($>10^9$ hash/detik) | **Dilarang keras**. Rentan rainbow table & tabrakan instan. |
| **SHA-1** | ❌ Kritis / Didepresiasi | Sangat Cepat | **Dilarang keras**. Telah dibobol secara matematis. |
| **Plain SHA-256** | ⚠️ Berisiko Tinggi | Terlalu Cepat | **Tidak memadai** untuk password tanpa key derivation adaptif. |
| **Bcrypt** | ✅ Aman / Standar | Lambat (Cost Factor Dinamis) | **Disarankan** (Cost factor minimal 12). |
| **Argon2id** | 🏆 Sangat Aman (Pilihan Terbaik) | Memory-Hard & Time-Hard | **Standar Emas OWASP** saat ini (tahan serangan GPU & ASIC). |

---

## 3. Playbook Remediasi: Prepared Statements & Parameterized Queries

Satu-satunya mitigasi efektif 100% terhadap SQL Injection adalah **Prepared Statements dengan Parameter Binding**. Escaping manual seperti `mysqli_real_escape_string` atau `addslashes` memiliki kelemahan bypass charset (misal *GBK multi-byte bypass*).

---

### A. Implementasi PHP (PDO) — Standar Produksi

```php
<?php
// Konfigurasi Koneksi PDO yang Aman
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // WAJIB: Nonaktifkan emulasi agar query diproses native oleh DB engine!
];
$pdo = new PDO("mysql:host=localhost;dbname=prod_db;charset=utf8mb4", $dbUser, $dbPass, $options);

// ==========================================
// 1. ENDPOINT REGISTRASI AMAN
// ==========================================
function registerUser(PDO $pdo, string $email, string $username, string $rawPassword): bool {
    // Hash password menggunakan Argon2id atau Bcrypt
    $hashedPassword = password_hash($rawPassword, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 1,
    ]);

    $stmt = $pdo->prepare(
        "INSERT INTO users (username, email, password_hash, created_at) 
         VALUES (:username, :email, :password_hash, NOW())"
    );

    return $stmt->execute([
        ':username'      => $username,
        ':email'         => $email,
        ':password_hash' => $hashedPassword,
    ]);
}

// ==========================================
// 2. ENDPOINT LOGIN AMAN
// ==========================================
function authenticateUser(PDO $pdo, string $email, string $rawPassword): ?array {
    // Ambil data user HANYA berdasarkan identifier unik
    $stmt = $pdo->prepare(
        "SELECT id, username, email, password_hash, role 
         FROM users 
         WHERE email = :email 
         LIMIT 1"
    );
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch();

    // Verifikasi hash dengan timing-attack safe function
    if ($user && password_verify($rawPassword, $user['password_hash'])) {
        // Cek jika algoritma perlu di-rehash karena cost factor dinaikkan
        if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($rawPassword, PASSWORD_ARGON2ID);
            $updateStmt = $pdo->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
            $updateStmt->execute([':hash' => $newHash, ':id' => $user['id']]);
        }

        // Mitigasi Session Fixation: Regenerasi Session ID
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        unset($user['password_hash']); // Hapus hash sebelum diteruskan ke session
        return $user;
    }

    // Pesan generic untuk mencegah user enumeration
    return null;
}
```

---

### B. Implementasi Node.js (PostgreSQL via `pg` / MySQL via `mysql2`)

```javascript
const bcrypt = require('bcrypt');
const BCRYPT_ROUNDS = 12;

// [A] REGISTRASI USER
async function register(db, username, email, password) {
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const sql = `
    INSERT INTO users (username, email, password_hash, created_at)
    VALUES ($1, $2, $3, NOW())
    RETURNING id, username, email
  `;
  const result = await db.query(sql, [username, email, hash]);
  return result.rows[0];
}

// [B] LOGIN USER
async function login(db, email, password) {
  const sql = `
    SELECT id, username, password_hash, role
    FROM users
    WHERE email = $1
    LIMIT 1
  `;
  const result = await db.query(sql, [email]);
  const user = result.rows[0];

  if (!user) {
    throw new Error('Email atau kata sandi tidak cocok.');
  }

  const isValid = await bcrypt.compare(password, user.password_hash);
  if (!isValid) {
    throw new Error('Email atau kata sandi tidak cocok.');
  }

  delete user.password_hash;
  return user;
}
```

---

### C. Implementasi Python (SQLAlchemy & Psycopg2)

```python
import bcrypt
from sqlalchemy.orm import Session
from sqlalchemy import text

# [A] REGISTRASI
def register_user(db: Session, username: str, email: str, password: str):
    salt = bcrypt.gensalt(rounds=12)
    pwd_bytes = password.encode('utf-8')
    hashed_pwd = bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

    # Menggunakan parameterized statement SQLAlchemy
    db.execute(
        text("INSERT INTO users (username, email, password_hash) VALUES (:user, :email, :pwd)"),
        {"user": username, "email": email, "pwd": hashed_pwd}
    )
    db.commit()

# [B] LOGIN
def authenticate_user(db: Session, email: str, password: str):
    result = db.execute(
        text("SELECT id, username, password_hash, role FROM users WHERE email = :email LIMIT 1"),
        {"email": email}
    ).fetchone()

    if result is None:
        return None

    user_id, username, stored_hash, role = result
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return {"id": user_id, "username": username, "role": role}

    return None
```

---

## 4. Pertahanan Berlapis Tambahan (*Defense-in-Depth*)

Selain prepared statements dan hashing yang kuat, terapkan kontrol pendukung berikut:

1. **Principle of Least Privilege (Hak Akses Database)**:
   - User database aplikasi web tidak boleh memiliki hak `SUPER`, `FILE`, `GRANT`, `DROP DATABASE`, atau akses membaca tabel sistem (`information_schema`).
2. **Mitigasi User Enumeration**:
   - Kembalikan respon kesalahan identik: *"Email atau kata sandi tidak valid"* baik saat email tidak ditemukan maupun saat password salah.
   - Sinkronisasi waktu respon (*time-constant response*) agar penyerang tidak bisa mengukur durasi pengecekan database vs hashing.
3. **Pencegahan Brute-Force & Credential Stuffing**:
   - Terapkan *Rate Limiting* berbasis IP dan username (maksimal 5 percobaan gagal per 15 menit).
   - Terapkan CAPTCHA adaptif (Cloudflare Turnstile) setelah 3 kegagalan berturut-turut.
4. **Session Fixation Defense**:
   - Selalu panggil `session_regenerate_id(true)` (PHP) atau buat session identifier baru secara kriptografis acak setelah otentikasi berhasil.
