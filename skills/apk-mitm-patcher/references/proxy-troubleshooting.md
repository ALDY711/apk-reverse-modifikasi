# Panduan Troubleshooting Intersepsi HTTPS Proxy

## Gejala Kegagalan dan Solusinya

| Gejala di Proxy / Logcat | Kemungkinan Penyebab | Tindakan Perbaikan |
|---|---|---|
| `SSLHandshakeException: CertPathValidatorException: Trust anchor for certification path not found` | Aplikasi tidak mempercayai User CA certificate | Gunakan `scripts/mitm_patch.py` untuk injeksi Network Security Config |
| `CLEARTEXT communication to host not permitted by network security policy` | Android 9+ memblokir HTTP biasa | Tambahkan `cleartextTrafficPermitted="true"` via `scripts/mitm_patch.py` |
| `SSLPeerUnverifiedException: Certificate pinning failure!` | Aplikasi mengimplementasikan pinning via OkHttp atau TrustManager di kode | Gunakan Frida SSL unpinning bypass |
| Proxy tidak mencatat request sama sekali | Aplikasi mengabaikan konfigurasi proxy sistem (misal: Flutter / gRPC) | Gunakan VPN mode (seperti ProxyDroid) atau iptables REDIRECT di device rooted |
| Koneksi timeout / No internet connection | Port proxy tidak dapat diakses dari device emulator/phone | Periksa IP listener Burp Suite (set ke `All interfaces` bukan `127.0.0.1`) |

Untuk memeriksa apakah APK memiliki sertifikat yang dibundel di dalam `assets/`, jalankan:
```bash
python skills/apk-mitm-patcher/scripts/cert_inspect.py --apk target.apk
```
