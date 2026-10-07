---
name: frida-dynamic-toolkit
description: "Dynamic instrumentation and analysis toolkit for Android using Frida. Generate production-ready bypass scripts for SSL pinning (OkHttp, Flutter, Cronet), root detection, biometric bypass, runtime crypto snooping, and automated hook generation for JNI and Java methods."
license: MIT — see LICENSE at repository root
compatibility: "Python 3.9+. Requires frida-tools on host and matching frida-server on Android device or emulator."
metadata:
  modified_by: "ALDY"
---

# Frida Dynamic Instrumentation Toolkit

> *Dimodifikasi dan disempurnakan oleh ALDY*

Toolkit komprehensif untuk instrumentasi dinamis aplikasi Android menggunakan Frida. Memfasilitasi bypass perlindungan keamanan (SSL pinning, root detection), inspeksi kriptografi runtime (AES/RSA/HMAC keys), serta interceptor batas Java Native Interface (JNI).

## Alur Kerja Analisis Dinamis

1. **Identifikasi Hambatan**:
   - Jika traffic HTTPS gagal terhubung (SSL handshake failed), gunakan `scripts/generate_bypass.py` dengan opsi `--type ssl`.
   - Jika aplikasi menutup seketika saat mendeteksi root/debugger, gunakan `scripts/generate_bypass.py` dengan opsi `--type root`.
   - Pelajari detail teknis di `references/ssl-pinning-matrix.md` dan `references/root-detection-matrix.md`.

2. **Ekstraksi Kunci Kriptografi & Dekripsi Runtime**:
   - Untuk memantau kunci enkripsi AES, inisialisasi IV, hashing HMAC, atau mendekripsi payload runtime, gunakan `scripts/crypto_monitor.py`:
     ```bash
     python skills/frida-dynamic-toolkit/scripts/crypto_monitor.py --out crypto_trace.js
     ```
   - Pelajari teknik ekstraksi kunci, penanganan AndroidKeyStore, dan hook native BoringSSL di `references/cryptographic-interception-and-key-extraction.md`.

3. **Intersepsi Layer Native & JNI**:
   - Untuk memantau parameter yang dikirim ke shared library `.so`, gunakan:
     ```bash
     python skills/frida-dynamic-toolkit/scripts/jni_hook_scaffold.py --mode env-strings --out jni_trace.js
     ```
   - Ikuti panduan performa di `references/frida-performance-and-stability.md`.

4. **Inventaris Lengkap**:
   - Daftar seluruh modul dan referensi dapat dilihat di `references/routing.md`.
