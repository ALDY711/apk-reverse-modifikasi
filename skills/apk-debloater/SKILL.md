---
name: apk-debloater
description: "Inspect, identify, and eliminate ad SDKs, telemetry, trackers, and bloatware from Android APKs. Features automated AndroidManifest.xml component neutering (disabling activities, services, receivers, providers for AdMob, UnityAds, AppLovin, Ironsource, Adjust, AppsFlyer) and generating DEX/smali no-op return stubs."
license: MIT — see LICENSE at repository root
compatibility: "Python 3.9+. Works with decompiled APK folders or direct AndroidManifest.xml files."
metadata:
  modified_by: "ALDY"
---

# APK Debloater & Ad Neutralizer

> *Dimodifikasi dan disempurnakan oleh ALDY*

Skill untuk mendeteksi, mendebloat, dan menetralisir iklan serta pelacak telemetry pada aplikasi Android secara aman tanpa merusak alur eksekusi aplikasi.

## Prosedur Debloating

1. **Pemindaian Komponen Iklan**:
   - Pindai manifest aplikasi untuk mengetahui keberadaan SDK iklan (AdMob, Unity, AppLovin, ironSource, dll):
     ```bash
     python skills/apk-debloater/scripts/debloat_manifest.py --manifest AndroidManifest.xml --scan
     ```
   - Lihat katalog lengkap di `references/ad-signature-catalogue.md`.

2. **Netralisasi Komponen (Manifest Neutering)**:
   - Nonaktifkan komponen iklan tanpa menghapus kelas Java agar tidak menyebabkan `ClassNotFoundException`:
     ```bash
     python skills/apk-debloater/scripts/debloat_manifest.py --manifest AndroidManifest.xml --neuter --out AndroidManifest_clean.xml
     ```
   - Pelajari mekanisme kerja neutering di `references/manifest-neutering.md`.

3. **Bypass Rewarded Ads (Fitur Terkunci Iklan)**:
   - Jika fitur aplikasi memerlukan reward iklan, buat stub smali no-op:
     ```bash
     python skills/apk-debloater/scripts/ad_stub_gen.py --type rewarded --out ./RewardedAd.smali
     ```

4. **Inventaris Modul**:
   - Lihat daftar lengkap modul dan referensi di `references/routing.md`.
