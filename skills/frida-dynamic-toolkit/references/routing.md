# Frida Dynamic Toolkit Routing Inventory

## Reference index

| Reference | Purpose |
|---|---|
| `references/ssl-pinning-matrix.md` | Matriks teknik bypass SSL pinning across OkHttp, TrustManager, Conscrypt, Flutter |
| `references/root-detection-matrix.md` | Daftar vektor deteksi root dan strategi neutralisasi |
| `references/cryptographic-interception-and-key-extraction.md` | Panduan intersepsi runtime kriptografi (AES, RSA, HMAC, Keystore) dan ekstraksi kunci/plaintext |
| `references/frida-performance-and-stability.md` | Panduan stabilitas, performa, dan troubleshooting runtime Frida |

## Script index

| Script | Purpose |
|---|---|
| `scripts/generate_bypass.py` | Generator skrip Frida untuk bypass SSL pinning dan root detection |
| `scripts/crypto_monitor.py` | Generator interceptor runtime Java Cryptography Architecture (AES, RSA, HMAC, IV) |
| `scripts/jni_hook_scaffold.py` | Generator hook untuk JNIEnv method calls dan exported native C/C++ functions |
