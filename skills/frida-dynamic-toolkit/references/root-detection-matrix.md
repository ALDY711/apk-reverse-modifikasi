# Android Root Detection Bypass Matrix

## Vektor Deteksi Root Umum

Aplikasi Android mendeteksi lingkungan rooted melalui beberapa indikator standar:

| Vektor Deteksi | Detail Pemeriksaan | Solusi Hook Frida |
|---|---|---|
| **Binary Paths** | Mencari `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/su` | Hook `java.io.File.exists()` dan kembalikan `false` jika path mengandung kata kunci root |
| **Command Execution** | Memanggil `Runtime.getRuntime().exec("which su")` atau `exec("su")` | Hook `java.lang.Runtime.exec()` dan intersep perintah bermasalah |
| **Build Tags** | Memeriksa `Build.TAGS` mengandung string `test-keys` | Timpa nilai `android.os.Build.TAGS` menjadi `release-keys` |
| **Package Manager** | Memeriksa package name terpasang seperti `com.topjohnwu.magisk`, `eu.chainfire.supersu` | Hook `PackageManager.getPackageInfo()` atau `getInstalledPackages()` |
| **RootBeer SDK** | SDK library populer `com.scottyab.rootbeer.RootBeer` | Hook method `isRooted()`, `isRootedWithoutBusyBoxCheck()` menjadi return `false` |
| **Syscall Native** | Menggunakan native `svc 0` untuk membaca `/proc/self/mounts` atau `which su` | KernelSU syscall masking atau Frida native hook libc `openat`/`access` |

## Cara Menggunakan Tool Otomasi
Gunakan skrip `scripts/generate_bypass.py` untuk menghasilkan bypass:
```bash
python skills/frida-dynamic-toolkit/scripts/generate_bypass.py --type root --out bypass_root.js
```
