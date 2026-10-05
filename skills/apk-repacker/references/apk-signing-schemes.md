# Android APK Signing Schemes (V1, V2, V3, V4)

## Perbandingan Skema Penandatanganan APK Android

| Skema | Nama Skema | Batas Minimal Android | Cara Kerja | Catatan Penting |
|---|---|---|---|---|
| **V1** | JAR Signature | Android 1.0+ | Memeriksa checksum SHA-1/SHA-256 per file di `META-INF/MANIFEST.MF` | Rentan terhadap modifikasi header ZIP; lambat diverifikasi saat instalasi |
| **V2** | APK Signature Scheme v2 | Android 7.0+ (API 24+) | Menyisipkan blok biner cryptographically signed di antara konten ZIP dan Central Directory | **Wajib di Android 11+**. Tidak boleh diubah byte-nya setelah di-sign |
| **V3** | APK Signature Scheme v3 | Android 9.0+ (API 28+) | Format identik dengan V2, ditambah dukungan rotasi kunci (key rotation proof) | Mengizinkan developer merotasi sertifikat signing |
| **V4** | APK Signature Scheme v4 | Android 11+ (API 30+) | File signature terpisah (`.apk.idsig`) untuk streaming install ADB | Berguna untuk deploy APK ukuran besar (>2GB) |

## Kesalahan Umum yang Membuat APK Gagal Diinstal
1. **Hanya menandatangani dengan `jarsigner` (V1)**: Pada Android 11 ke atas, sistem operasi akan menolak instalasi dengan pesan `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.
2. **Menjalankan `zipalign` SETELAH `apksigner`**: `zipalign` mengubah byte offset arsip ZIP, yang langsung merusak blok hash biner V2/V3. Urutan yang **wajib**:
   `Zip/Pack` ➔ `zipalign` ➔ `apksigner sign` ➔ `apksigner verify`.

Gunakan `scripts/apk_signer.py` untuk memastikan penandatanganan V1, V2, dan V3 terpasang sekaligus.
