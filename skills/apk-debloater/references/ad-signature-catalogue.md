# Ad and Telemetry SDK Signatures Catalogue

## Daftar Package Name SDK Iklan & Pelacak Terpopuler

Tabel berikut memetakan jaringan iklan komersial utama dengan signature package Java mereka:

| Network / Vendor | Package Signatures | Risiko jika Dihapus Kasar | Solusi |
|---|---|---|---|
| **Google AdMob** | `com.google.android.gms.ads`, `com.google.ads` | Crash saat `MobileAds.initialize()` | Neuter manifest + stub callback |
| **Unity Ads** | `com.unity3d.ads`, `com.unity3d.services` | Null pointer pada Unity UI game loop | Nonaktifkan komponen manifest |
| **AppLovin / MAX** | `com.applovin` | Gagal mediasi antar-jaringan iklan | Neuter manifest |
| **ironSource** | `com.ironsource`, `com.supersonicads` | Background sync error | Neuter manifest |
| **Facebook Audience Network** | `com.facebook.ads` | Login/auth crash jika digabung dengan FB SDK | Matikan `<activity>` iklan FB |
| **Adjust SDK** | `com.adjust.sdk` | Gagal tracking atribusi install | Neuter broadcast receiver |
| **AppsFlyer** | `com.appsflyer` | Telemetry error | Neuter broadcast receiver |

Gunakan `scripts/debloat_manifest.py` untuk pemindaian otomatis terhadap signature di atas.
