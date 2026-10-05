# Android SSL Pinning Bypass Matrix

## Gambaran Umum
SSL Pinning mengikat aplikasi ke sertifikat server atau public key tertentu untuk mencegah intersepsi HTTPS (Man-In-The-Middle / MITM). Berbagai framework Android mengimplementasikan pinning pada lapisan yang berbeda.

| Layer / Framework | Mekanisme Deteksi | Titik Hook Frida / Solusi |
|---|---|---|
| **Android OS (API 24+)** | `NetworkSecurityConfig` (`res/xml/network_security_config.xml`) | `android.security.net.config.NetworkSecurityTrustManager.checkPins` atau patch manifest |
| **Java Standard** | `javax.net.ssl.X509TrustManager`, `SSLContext.init()` | Buat custom trust manager yang mengizinkan semua sertifikat dan ganti pada `SSLContext.init` |
| **OkHttp 3 / OkHttp 4** | `okhttp3.CertificatePinner.check(String, List)` | Hook `CertificatePinner.check` agar return void tanpa melempar `SSLPeerUnverifiedException` |
| **Conscrypt** | `org.conscrypt.TrustManagerImpl.checkTrustedRecursive` | Hook `checkTrustedRecursive` return daftar sertifikat kosong/valid |
| **Apache HttpClient** | `org.apache.http.conn.ssl.SSLSocketFactory` | Set `ALLOW_ALL_HOSTNAME_VERIFIER` |
| **WebView** | `android.webkit.WebViewClient.onReceivedSslError` | Hook `handler.proceed()` saat error SSL terjadi |
| **Flutter / Dart** | BoringSSL / `libflutter.so` (`ssl_crypto_x509_session_verify_cert_chain`) | Byte patch pada `.so` atau pattern scan memori untuk bypass return code verifikasi |
| **Cronet (Chromium)** | Native Cronet verifier | Hook `CronetUrlRequestContext` atau patch native library |

## Cara Menggunakan Tool Otomasi
Gunakan skrip `scripts/generate_bypass.py` untuk menghasilkan payload bypass:
```bash
python skills/frida-dynamic-toolkit/scripts/generate_bypass.py --type ssl --out unpin.js
```
