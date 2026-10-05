# Zipalign and ZIP Compression Rules in Android

## Mengapa Zipalign 4-Byte Wajib?

Android OS memetakan file resource dan biner native langsung dari dalam APK ke memori RAM virtual menggunakan syscall `mmap()`.

Untuk performa efisien dan arsitektur CPU ARM/x86:
- **Batasan 4-Byte**: Data yang tidak terkompresi harus dimulai pada kelipatan 4 byte dari awal file.
- **Batasan 4KB Page Align (`-p`)**: Shared library `.so` yang tidak dikompresi harus berada pada batas halaman memori 4096-byte (4KB) agar runtime linker Android (`/system/bin/linker64`) dapat memuatnya langsung dari memori tanpa mengekstraknya ke penyimpanan perangkat (`extractNativeLibs="false"`).

## Aturan Kompresi File di APK

| File / Folder | Tipe Kompresi | Alasan |
|---|---|---|
| `resources.arsc` | **STORED (Uncompressed)** | Harus dibaca langsung via memory mapping tanpa dekompresi overhead |
| `classes.dex`, `classes2.dex` | **DEFLATED (Compressed)** | Boleh dikompresi; runtime ART memuat DEX ke heap/oat |
| `lib/<abi>/*.so` | **STORED** (jika page-aligned) atau **DEFLATED** | Uncompressed menghemat ruang penyimpanan instalasi |
| `assets/*` | **DEFLATED** (kecuali video/audio/font besar) | Standar kompresi aset |

Gunakan tool `scripts/repack_pipeline.py` untuk mengemas folder dengan kepatuhan zipalign penuh.
