# Weak Ciphers, Misconfigurations & Mobile Cryptographic Pitfalls

> Katalog taksonomi celah kriptografi umum pada aplikasi Android dan panduan perbaikannya berdasarkan standar OWASP MASVS-CRYPTO.

---

## 1. Bahaya AES/ECB (Electronic Codebook) Mode

### Masalah
Dalam mode ECB, blok plaintext yang identik selalu menghasilkan blok ciphertext yang identik jika dienkripsi dengan kunci yang sama. Hal ini menghilangkan *semantic security* dan memungkinkan penyerang melihat pola data tersembunyi (seperti format citra BMP atau format JSON).

```java
// SANGAT BERBAHAYA - Mode ECB default jika tidak menyebutkan mode:
Cipher cipher = Cipher.getInstance("AES");
Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

### Remediasi
Gunakan mode **AES-GCM** yang terotentikasi (*Authenticated Encryption with Associated Data / AEAD*):
```java
// AMAN & TEROTENTIKASI:
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

---

## 2. Penggunaan Initialization Vector (IV) yang Statis atau Nol

### Masalah
IV bertindak sebagai nonce acak untuk mencegah enkripsi dua pesan yang sama menghasilkan ciphertext yang sama. Menggunakan byte array nol (`new byte[16]`) atau string statis merusak keamanan:
- Pada mode **CBC**: Menyebabkan kerentanan *chosen-plaintext attack* dan *watermarking*.
- Pada mode **GCM**: Pengulangan IV (Nonce Reuse) dengan kunci yang sama menyebabkan kebocoran *GHASH authentication key*, sehingga penyerang dapat memalsukan pesan.

```java
// BERBAHAYA - IV statis berulang:
byte[] staticIv = "1234567890123456".getBytes();
IvParameterSpec ivSpec = new IvParameterSpec(staticIv);
```

### Remediasi
Selalu buat IV acak baru menggunakan `SecureRandom` pada setiap enkripsi:
```java
byte[] iv = new byte[12]; // 12-byte IV standar untuk AES-GCM
SecureRandom secureRandom = new SecureRandom();
secureRandom.nextBytes(iv);
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
```

---

## 3. Derivasi Kunci yang Lemah (Insecure Key Derivation)

### Masalah
Menghasilkan kunci kriptografis dari password pengguna hanya dengan hashing sederhana (`MD5(password)` atau `SHA256(password)`) tanpa salt atau dengan iterasi rendah sangat rentan terhadap *offline dictionary & brute-force attacks*.

### Remediasi
Gunakan algoritma derivasi kunci dengan *memory-hard function* atau *work factor tinggi*:
- **PBKDF2WithHmacSHA256** dengan minimal **100.000 iterasi** dan salt acak minimal 16-byte.
- **Argon2id** atau **scrypt** untuk perlindungan maksimal dari ASIC/GPU brute-forcing.
