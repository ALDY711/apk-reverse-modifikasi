---
name: mobile-crypto-inspector
description: "Audit, analyze, and inspect Android and mobile cryptographic security, Keystore implementations, weak ciphers, hardcoded secrets, encrypted storage, and runtime crypto operations."
---

# Mobile Cryptography & Keystore Inspector

> Toolkit dan panduan komprehensif untuk mengaudit, menganalisis, dan memvalidasi keamanan implementasi kriptografi pada aplikasi Android / Mobile. Meliputi inspeksi Android Keystore (TEE/StrongBox), deteksi cipher usang (ECB, DES, MD5), hardcoded keys, static IVs, audit SQLite/SQLCipher terenkripsi, serta pembuatan hook Frida runtime kriptografi.

---

## 1. Arsitektur Keamanan Kriptografi Mobile

```
+-------------------------------------------------------------------------------+
|                       APLIKASI MOBILE (DEX / NATIVE)                          |
+-------------------------------------------------------------------------------+
         |                                           |
         v                                           v
+-------------------------------+       +---------------------------------------+
|   ANDROID KEYSTORE PROVIDER   |       |       PENGOLAHAN KRIPTO LOKAL         |
|  - TEE / StrongBox Hardware   |       |  - javax.crypto.Cipher                |
|  - KeyGenParameterSpec        |       |  - SecretKeySpec / PBEKeySpec         |
|  - Biometric / Auth-Bound Key |       |  - SecureRandom / IvParameterSpec     |
|  - MasterKey (EncryptedPrefs) |       |  - SQLCipher / Encrypted SQLite       |
+-------------------------------+       +---------------------------------------+
         |                                           |
         v                                           v
[ Audit: Hardware Backing & Alias ]     [ Audit: Mode Cipher, Hardcoded Key, IV ]
```

---

## 2. Alur Kerja Audit Kriptografi (4 Tahap)

### Tahap 1: Pemindaian Statis DEX / Smali / Source Code
Pindai penggunaan algoritma kriptografi yang lemah atau tidak aman:
```bash
# Pindai file Smali / direktori proyek untuk mendeteksi cipher lemah & static key
python skills/mobile-crypto-inspector/scripts/crypto_smali_scanner.py --dir ./smali_out

# Output dalam format JSON untuk integrasi CI/CD
python skills/mobile-crypto-inspector/scripts/crypto_smali_scanner.py --dir ./smali_out --json
```

### Tahap 2: Inspeksi Android Keystore & Key Protection
Audit apakah kunci kriptografi disimpan dengan benar di Android Keystore:
```bash
# Inspeksi kode atau manifest terkait Keystore, MasterKey, dan EncryptedSharedPreferences
python skills/mobile-crypto-inspector/scripts/keystore_inspector.py --target ./app_source
```

### Tahap 3: Audit Penyimpanan Terenkripsi (Encrypted Storage)
Verifikasi apakah database lokal atau shared preferences menggunakan enkripsi yang kuat:
```bash
# Audit database SQLite, SQLCipher, dan XML preferences
python skills/mobile-crypto-inspector/scripts/encrypted_storage_audit.py --path ./data_dir
```

### Tahap 4: Pelacakan Kriptografi Dinamis (Runtime Tracing)
Hasilkan script Frida untuk memonitor kunci dan payload enkripsi di memori secara realtime:
```bash
# Generate script Frida hook Cipher, Mac, dan KeyStore
python skills/mobile-crypto-inspector/scripts/runtime_crypto_hook_gen.py --out trace_crypto.js
```

---

## 3. Matriks Kerentanan Kriptografi Umum

| Kerentanan | Tingkat Risiko | Ciri / Pola Kode | Mitigasi Standar |
|---|---|---|---|
| **AES/ECB Mode** | KRITIS | `Cipher.getInstance("AES")` atau `"AES/ECB/PKCS5Padding"` | Gunakan `AES/GCM/NoPadding` dengan authentication tag 128-bit. |
| **Static / Zero IV** | TINGGI | `byte[] iv = new byte[16];` tanpa SecureRandom | Hasilkan IV acak via `SecureRandom` untuk setiap enkripsi. |
| **Hardcoded Secret Key** | KRITIS | String statis dikonversi ke `SecretKeySpec` | Simpan kunci di Android Keystore dengan hardware backing. |
| **Weak Hash / MAC** | SEDANG | Penggunaan `MD5`, `SHA-1`, atau DES/3DES | Migrasi ke SHA-256/SHA-512 atau HMAC-SHA256. |
| **Insecure PRNG** | TINGGI | `Random.setSeed()` atau predictable seed | Gunakan `java.security.SecureRandom` tanpa manual seed. |
| **Backup Leaks** | SEDANG | `android:allowBackup="true"` pada AndroidManifest | Setel `android:allowBackup="false"` agar DB/Keystore tidak terekspor via ADB. |

---

## 4. Panduan Referensi Teknis

- [Android Keystore & Hardware Backing](references/android-keystore-and-hardware-backing.md): Arsitektur TEE, StrongBox, KeyGenParameterSpec, dan autentikasi biometrik.
- [Weak Ciphers & Misconfigurations](references/weak-ciphers-and-misconfigurations.md): Taksonomi kerentanan ECB, padding oracle, nonce reuse, dan derivasi kunci lemah.
- [SQLCipher & Encrypted Storage](references/sqlcipher-and-encrypted-storage.md): Pengamanan database SQLite terenkripsi, MasterKey migration, dan SharedPrefs.
- [Frida Crypto Tracing Recipes](references/frida-crypto-tracing-recipes.md): Kumpulan resep hook Frida untuk melacak operasi kriptografi Java dan Native C/C++.
