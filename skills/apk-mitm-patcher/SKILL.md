---
name: apk-mitm-patcher
description: "Prepare Android APKs for HTTPS inspection and MITM interception (Burp Suite, mitmproxy, Charles). Injects Network Security Config (NSC) to trust user/custom CA certificates, removes cleartext restrictions, patches AndroidManifest.xml, and validates certificate chain bypasses across Android 7.0+ (API 24 to 35)."
license: MIT — see LICENSE at repository root
compatibility: "Python 3.9+. Operates on unpacked APK directories or standalone XML/APK files."
metadata:
  modified_by: "ALDY"
---

# APK MITM Patcher

> *Dimodifikasi dan disempurnakan oleh ALDY*

Skill untuk mempersiapkan aplikasi Android agar dapat diintersepsi oleh proxy HTTPS (Burp Suite, mitmproxy, Charles Proxy) dengan memodifikasi Network Security Config (NSC) dan mengizinkan user CA certificates.

## Prosedur Patching Intersepsi

1. **Pemeriksaan Sertifikat Terbundel**:
   - Periksa apakah APK membawa file CA kustom atau certificate pinning bawaan di `assets/`:
     ```bash
     python skills/apk-mitm-patcher/scripts/cert_inspect.py --apk target.apk
     ```

2. **Injeksi Network Security Config**:
   - Lakukan patching pada folder proyek hasil decompile (apktool):
     ```bash
     python skills/apk-mitm-patcher/scripts/mitm_patch.py --dir ./unpacked_apk
     ```
   - Skrip akan membuat file `res/xml/network_security_config.xml` dan menyisipkan atribut `android:networkSecurityConfig` serta `android:usesCleartextTraffic="true"` ke `AndroidManifest.xml`.
   - Baca referensi teknis di `references/network-security-config-deepdive.md`.

3. **Repack & Signing**:
   - Setelah patching selesai, repack dan sign ulang APK menggunakan build tool Anda atau `repack.py`.

4. **Troubleshooting**:
   - Jika koneksi tetap gagal atau memunculkan peringatan sertifikat, pelajari tabel panduan di `references/proxy-troubleshooting.md`.

5. **Inventaris**:
   - Lihat daftar lengkap modul di `references/routing.md`.
