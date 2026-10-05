---
name: apk-repacker
description: "Repackage, align, and sign modified Android APKs into installable artifacts. Enforces 4-byte zipalign, 4KB native library page alignment, preserves uncompressed resources.arsc, strips previous vendor signatures, and applies APK Signature Scheme V1, V2, and V3 via apksigner for clean installation on Android 7.0 through 15."
license: MIT — see LICENSE at repository root
compatibility: "Python 3.9+. Uses zipalign and apksigner from Android SDK build-tools or PATH with fallback."
metadata:
  modified_by: "ALDY"
---

# APK Repacker & Signing Pipeline

> *Dimodifikasi dan disempurnakan oleh ALDY*

Skill untuk mengemas ulang direktori hasil modifikasi, menata arsip ZIP sesuai standar Android (4-byte zipalign & kompresi STORED untuk resources.arsc), serta menandatangani APK dengan skema V1, V2, dan V3 agar langsung dapat diinstal dan dijalankan di perangkat Android fisik maupun emulator.

## Alur Kerja Pengemasan APK Siap Pakai

1. **Persiapan Direktori Modifikasi**:
   - Pastikan file yang dimodifikasi (DEX, manifest, assets, atau `.so`) sudah berada di direktori kerja.
   - Pahami aturan kompresi di `references/zipalign-and-compression.md`.

2. **Repack, Zipalign & Sign Otomatis**:
   - Jalankan pipeline pengemasan lengkap dengan perintah:
     ```bash
     python skills/apk-repacker/scripts/repack_pipeline.py --dir ./unpacked_dir --out ./ready.apk
     ```
   - Skrip akan otomatis membersihkan signature lama di `META-INF`, mempertahankan entri `resources.arsc` tanpa kompresi, menjalankan zipalign 4-byte, dan menandatangani dengan debug keystore.

3. **Verifikasi Signature Sebelum Deploy**:
   - Pastikan bahwa signature V1 dan V2/V3 valid agar tidak terjadi error `INSTALL_PARSE_FAILED_NO_CERTIFICATES`:
     ```bash
     python skills/apk-repacker/scripts/apk_signer.py --verify ./ready.apk
     ```
   - Pelajari detail perbedaan skema signing di `references/apk-signing-schemes.md`.

4. **Inventaris Modul**:
   - Lihat daftar lengkap modul dan referensi di `references/routing.md`.
