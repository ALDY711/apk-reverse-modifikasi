# SQLCipher & Secure Encrypted Storage in Android

> Panduan audit dan implementasi penyimpanan database terenkripsi, Jetpack Security `EncryptedSharedPreferences`, dan mitigasi kebocoran storage lokal.

---

## 1. Arsitektur SQLCipher

SQLCipher menyediakan ekstensi enkripsi AES-256 transparan penuh untuk database SQLite:

```
+-------------------------------------------------------------------------------+
|                      APLIKASI ANDROID / ROOM DATABASE                         |
+-------------------------------------------------------------------------------+
                                        | (Kueri SQL standar)
                                        v
+-------------------------------------------------------------------------------+
|                             SQLCIPHER ENGINE                                  |
|  - Setiap page database (umumnya 4096 byte) dienkripsi secara independen      |
|  - Kunci diturunkan via PBKDF2 (default 256.000 iterasi)                      |
|  - Menggunakan HMAC-SHA512 atau HMAC-SHA1 untuk integritas per page           |
+-------------------------------------------------------------------------------+
                                        | (Ciphertext murni)
                                        v
                           [ Berkas /data/data/<pkg>/databases/*.db ]
```

---

## 2. Implementasi Jetpack Security (`EncryptedSharedPreferences`)

Cara aman menyimpan token otentikasi dan data kredensial di Android:

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

// 1. Buat atau ambil MasterKey yang dilindungi Android KeyStore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .setUserAuthenticationRequired(false)
    .build()

// 2. Inisialisasi EncryptedSharedPreferences
val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_user_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// 3. Simpan data (kunci dan isi akan terenkripsi otomatis di disk)
securePrefs.edit()
    .putString("auth_token", "jwt_token_here")
    .apply()
```

---

## 3. Titik Lemah yang Perlu Diaudit

1. **Hardcoded Passphrase pada SQLCipher**:
   Banyak aplikasi menginisialisasi SQLCipher dengan string tetap di dalam kode:
   `SQLiteDatabase.loadLibs(context);`
   `SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(file, "HARDCODED_KEY_123", null);`
   *Risiko*: Siapa pun yang mendekomplikasi APK dapat langsung membaca database.

2. **File Cache & Temporary Data**:
   Aplikasi sering mengenkripsi database utama tetapi meninggalkan cache HTTP atau gambar terdekripsi di folder eksternal `/sdcard/Android/data/<pkg>/cache/`.
