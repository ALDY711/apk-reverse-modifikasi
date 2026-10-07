# Network Security Config (NSC) Deep Dive

## Spesifikasi Android Network Security Config

Mulai Android 7.0 (API 24), Android memperkenalkan file konfigurasi keamanan deklaratif XML untuk mengontrol perilaku koneksi jaringan aplikasi tanpa mengubah kode Java.

### Struktur XML Lengkap untuk Intersepsi Burp/Proxy

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Konfigurasi global untuk seluruh domain -->
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <!-- Percayai CA bawaan sistem Android -->
            <certificates src="system" />
            <!-- Percayai CA yang diinstal pengguna (Burp Suite, Charles, mitmproxy) -->
            <certificates src="user" />
        </trust-anchors>
    </base-config>

    <!-- Izinkan override saat aplikasi di-debug -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### Integrasi ke AndroidManifest.xml
Tambahkan atribut berikut ke tag `<application>`:
```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="true"
    ...>
```

Gunakan skrip `scripts/mitm_patch.py` untuk mengotomatisasi injeksi XML dan atribut manifest di atas.

### Eliminasi Pin-Set Deklaratif
Jika aplikasi mengonfigurasi public key pinning langsung di NSC XML:
```xml
<!-- Pola Pinning di res/xml/network_security_config.xml -->
<domain-config>
    <domain includeSubdomains="true">api.target.com</domain>
    <pin-set expiration="2027-01-01">
        <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmElZhWvWAhxGOVS3=</pin>
    </pin-set>
</domain-config>
```
* **Solusi Patch:** Hapus seluruh elemen `<pin-set>...</pin-set>` atau ganti isi file NSC dengan konfigurasi permisif `base-config` di atas.

### Penanganan Mutual TLS (mTLS) & Client Certificate
Beberapa aplikasi perbankan atau enterprise menggunakan otentikasi dua arah (mTLS) di mana aplikasi mengirim sertifikat klien (`.p12`, `.pfx`, atau `.bks`):
1. **Lokasi Sertifikat Klien:** Cari file biner PKCS#12 di `assets/`, `res/raw/`, atau direktori internal aplikasi (`grep -rn "KeyStore.getInstance(\"PKCS12\")"`).
2. **Ekstraksi Password Kriptografi:**
   Password keystore klien biasanya diturunkan atau disimpan statis di kode Java atau native:
   ```bash
   grep -rn "KeyStore.load" <decompiled_sources>
   ```
   Atau pasang hook Frida pada `KeyStore.load(InputStream stream, char[] password)` untuk mencetak password dalam format teks biasa (*plaintext*).
3. **Pemasangan di Proxy:** Pasang file `.p12` beserta password yang diekstrak ke dalam Burp Suite (*User Options -> TLS -> Client Certificates*) atau mitmproxy (`--set client_certs=client.pem`) agar proxy dapat bernegosiasi mTLS dengan server.

