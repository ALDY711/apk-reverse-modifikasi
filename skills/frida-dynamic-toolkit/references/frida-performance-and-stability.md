# Frida Performance and Stability Guide

## Praktik Terbaik Stabilitas Hook

Saat melakukan instrumentasi dinamis menggunakan Frida pada target Android:

1. **Gunakan Java.perform() Secara Efisien**: Jangan panggil `Java.perform()` berulang-ulang di dalam loop synchronous. Jalankan sekali pada root skrip.
2. **Hindari String Concat Berat pada Fast Loops**: Memanggil `console.log` pada method yang dipanggil ribuan kali per detik akan menyebabkan lag atau process freeze. Gunakan buffering atau filter bersyarat.
3. **Pemberian Timeout untuk Native Libraries**: Jika hooking `.so` yang di-load secara dinamis via `System.loadLibrary`, gunakan interceptor pada `dlopen` / `android_dlopen_ext` atau tunggu hingga modul terpetakan sebelum memanggil `Module.findExportByName`.
4. **Monitoring Kripto**: Gunakan skrip `scripts/crypto_monitor.py` dengan opsi `--stack-trace` hanya saat mengidentifikasi lokasi pemanggilan spesifik untuk meminimalkan beban memori.
5. **JNI Boundary Tracking**: Gunakan `scripts/jni_hook_scaffold.py` untuk menargetkan fungsi native spesifik daripada melakukan hooking global pada seluruh export table.
