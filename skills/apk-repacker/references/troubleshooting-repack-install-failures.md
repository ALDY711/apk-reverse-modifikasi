# Troubleshooting Kegagalan Instalasi & Eksekusi APK Hasil Modifikasi

Panduan komprehensif penanganan 10 masalah umum saat memasang (*sideload*) dan menjalankan berkas APK hasil *repack* di perangkat Android fisik maupun emulator.

---

## 1. Katalog Error Instalasi (`adb install`) & Solusinya

### A. `INSTALL_PARSE_FAILED_NO_CERTIFICATES`
* **Gejala**: Instalasi ditolak di Android 11, 12, 13, 14, atau 15.
* **Penyebab**: APK hanya ditandatangani dengan skema V1 (`jarsigner`), sementara Android 11+ mewajibkan skema **V2** (full-file binary hash) atau **V3**.
* **Solusi**:
  Gunakan `apksigner` resmi dengan flag:
  ```powershell
  apksigner sign --ks debug.keystore --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true output.apk
  ```

---

### B. `INSTALL_FAILED_INVALID_APK` (atau Error Alignment `[-124]`)
* **Gejala**: Sistem Android menolak memproses paket ZIP.
* **Penyebab**:
  1. Berkas `resources.arsc` terkompresi (mode `DEFLATED`). Android **mewajibkan** file ini dalam mode **`STORED` (tanpa kompresi)**.
  2. Berkas belum diselaraskan ke batas 4-byte.
* **Solusi**:
  1. Simpan `resources.arsc` dengan `ZIP_STORED` saat membuat arsip ZIP.
  2. Jalankan `zipalign`:
     ```powershell
     zipalign -f -p 4 unaligned.apk aligned.apk
     ```
     *(Parameter `-p 4` memastikan pustaka `.so` diselaraskan ke halaman memori 4KB).*

---

### C. `INSTALL_FAILED_UPDATE_INCOMPATIBLE`
* **Gejala**: Instalasi update gagal di atas aplikasi yang sudah terpasang di HP.
* **Penyebab**: Aplikasi di HP ditandatangani dengan kunci resmi (*production keystore* vendor), sedangkan APK hasil modifikasi Anda ditandatangani dengan *debug keystore* yang berbeda.
* **Solusi**:
  1. Hapus (*uninstall*) aplikasi versi lama dari HP terlebih dahulu:
     ```powershell
     adb uninstall <nama.package>
     ```
  2. Pasang APK modifikasi Anda yang baru:
     ```powershell
     adb install -r output.apk
     ```

---

### D. `INSTALL_FAILED_CONFLICTING_PROVIDER`
* **Gejala**: Muncul error menyebutkan `ContentProvider` sudah terdaftar oleh aplikasi lain.
* **Penyebab**: Anda mengubah `packageName` di manifest untuk membuat klon aplikasi, tetapi atribut `android:authorities` pada tag `<provider>` masih sama dengan aplikasi asli.
* **Solusi**:
  Buka `AndroidManifest.xml`, cari semua tag `<provider>`, lalu ganti `android:authorities` agar unik (misalnya tambahkan akhiran `.mod`).

---

### E. `INSTALL_FAILED_DEXOPT` / `VerifyError`
* **Gejala**: Aplikasi ditolak saat fase optimasi bytecode Dalvik, atau *crash* seketika saat kelas pertama kali dipanggil.
* **Penyebab**:
  1. Ada instruksi percabangan yang melompati instruksi `move-result` (mengakibatkan verifier ART kehilangan referensi hasil eksekusi).
  2. Penggunaan tipe register yang tidak cocok (misalnya memasukkan objek ke register float/double).
* **Solusi**:
  Gunakan skrip `dex_check_verifier.py` untuk mengidentifikasi method yang bermasalah sebelum mengemas ulang APK.

---

### F. `INSTALL_FAILED_VERSION_DOWNGRADE`
* **Gejala**: Android menolak instalasi karena versi APK lebih rendah dari yang sudah terpasang.
* **Solusi**:
  Tambahkan flag `-d` pada ADB:
  ```powershell
  adb install -r -d output.apk
  ```
  Atau naikkan nilai `android:versionCode` di `AndroidManifest.xml`.

---

## 2. Masalah Silent Crash Saat Aplikasi Dibuka (*Runtime Failures*)

Jika instalasi berhasil (`Success`), tetapi aplikasi langsung tertutup sendiri (*force close*) saat dibuka:

### A. Proteksi Native Integrity / Signature Check (`lib*.so`)
* **Penyebab**: Pustaka C++ membaca hash signature APK saat *cold start*. Karena APK ditandatangani dengan *debug key*, pustaka native memanggil `exit(0)` atau sengaja melakukan *null dereference* (crash terencana).
* **Solusi**:
  1. Buka `logcat` saat aplikasi dibuka:
     ```powershell
     adb logcat -s AndroidRuntime DEBUG
     ```
  2. Cari apakah crash terjadi di dalam file `.so` (tombstone).
  3. Lakukan patch pada method native pemanggil atau gunakan modul Frida/LSPosed untuk me-mock hash signature asli saat runtime.

### B. Masalah Split APK / App Bundle (Missing Splits)
* **Penyebab**: Aplikasi modern menggunakan format Split APK (misal `base.apk`, `split_config.arm64_v8a.apk`, `split_config.id.apk`). Jika hanya `base.apk` yang dipasang, aplikasi akan kehilangan resource bahasa atau library arsitektur CPU.
* **Solusi**:
  1. Gabungkan (*merge*) seluruh split APK menjadi satu APK monolitik sebelum memodifikasi.
  2. Atau pasang seluruh split bersamaan menggunakan:
     ```powershell
     adb install-multiple base.apk split_config.arm64_v8a.apk split_config.id.apk
     ```

---

## 3. Checklist Verifikasi Akhir Sebelum Distribusi APK

Gunakan daftar periksa berikut agar APK modifikasi Anda dijamin 100% stabil:

- [ ] `resources.arsc` berstatus `STORED` (tidak terkompresi).
- [ ] 4-Byte Zipalign berhasil diverifikasi (`zipalign -c -v 4 file.apk`).
- [ ] Signature V1, V2, dan V3 berstatus `true` (`apksigner verify -v file.apk`).
- [ ] Tidak ada konflik authority provider pada perangkat target.
- [ ] Diuji coba cold-start menggunakan `adb install -r` dan `scrcpy`.
