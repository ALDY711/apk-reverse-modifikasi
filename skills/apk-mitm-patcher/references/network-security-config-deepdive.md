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
