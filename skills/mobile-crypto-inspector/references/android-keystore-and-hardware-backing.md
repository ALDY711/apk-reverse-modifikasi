# Android KeyStore & Hardware-Backed Key Security

> Panduan mendalam tentang arsitektur Android KeyStore Provider, isolasi kunci berbasis hardware (TEE & StrongBox), konfigurasi `KeyGenParameterSpec`, dan autentikasi biometrik.

---

## 1. Arsitektur Isolasi Android KeyStore

Android KeyStore melindungi material kunci kriptografis dari ekstraksi langsung. Kunci disimpan di lingkungan perangkat keras terisolasi:

```
+-------------------------------------------------------------------------------+
|                            APLIKASI ANDROID (USERSPACE)                       |
|   - KeyStore.getInstance("AndroidKeyStore")                                   |
|   - Meminta operasi Enkripsi/Dekripsi/Signing lewat IPC Binder               |
+-------------------------------------------------------------------------------+
                                        | (IPC / Keystore Daemon)
                                        v
+-------------------------------------------------------------------------------+
|                       HARDWARE SECURITY MODULE (HSM)                          |
|                                                                               |
|   [ 1. Trusted Execution Environment (TEE) ]                                  |
|   - ARM TrustZone kernel terisolasi                                           |
|   - Kunci master dienkripsi dengan hardware root key (eFuse)                 |
|                                                                               |
|   [ 2. StrongBox Keymaster (Dedicated Chip) ]                                 |
|   - Chip mikrokontroler fisik independen (Secure Element / Titan M)           |
|   - Proteksi tamper fisik & side-channel attack resistant                     |
+-------------------------------------------------------------------------------+
```

---

## 2. Praktik Terbaik Pembuatan Kunci via `KeyGenParameterSpec`

Pola kode Java/Kotlin yang aman untuk menginisialisasi kunci AES-256 di Keystore:

```java
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public SecretKey generateSecureHardwareKey(String alias) throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, 
        "AndroidKeyStore"
    );

    KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
    )
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true) // Memerlukan PIN/Biometrik
    .setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG); // Valid 30 detik

    // Mengaktifkan isolasi StrongBox jika perangkat mendukung
    if (isStrongBoxSupported()) {
        builder.setIsStrongBoxBacked(true);
    }

    keyGenerator.init(builder.build());
    return keyGenerator.generateKey();
}
```

---

## 3. Checklist Audit Keamanan KeyStore

- [ ] **Hardware Backing**: Apakah aplikasi memeriksa apakah kunci berada di dalam hardware (`KeyInfo.isInsideSecureHardware()`)?
- [ ] **Algoritma Otentikasi**: Apakah menggunakan mode `GCM` atau `CBC` dengan HMAC yang valid, bukan `ECB`?
- [ ] **User Authentication Gate**: Untuk transaksi finansial atau data sensitif, apakah `setUserAuthenticationRequired(true)` diaktifkan?
- [ ] **Android Backup Protection**: Apakah `android:allowBackup="false"` diatur di `AndroidManifest.xml` untuk mencegah kloning data aplikasi via `adb backup`?
- [ ] **Key Expiration**: Apakah `setKeyValidityStart` dan `setKeyValidityEnd` diterapkan untuk rotasi kunci berkala?
