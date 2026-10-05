# Panduan Cepat (Bahasa Indonesia)

> *Dimodifikasi dan disempurnakan oleh ALDY*

**Load this when**: Anda menginginkan ringkasan alur kerja cepat langkah-demi-langkah dalam Bahasa Indonesia untuk setup, rekon target, patching bedah DEX/SO, repack, dan pengujian build.

**What this answers**: panduan praktis menjalankan 4 Gate, perintah CLI utama apk_cli.py, persiapan lingkungan kerja, dan rekon bertahap.

---

## Prasyarat

### Wajib
- **Python 3.9+** — [Download](https://python.org/downloads/)
- **Java JDK 11+** — Diperlukan untuk signing APK

### Direkomendasikan
- **adb** (Android Debug Bridge) — Untuk komunikasi dengan perangkat
- **jadx** — Decompiler APK visual
- **apktool** — Disassembly/reassembly APK
- **zipalign** + **apksigner** — Dari Android SDK Build Tools
- **Frida** — Analisis dinamis (perlu perangkat rooted)

### Cek Lingkungan
```bash
# Jalankan pemeriksaan otomatis
python setup.py

# Atau cek saja tanpa install
python setup.py --check
```

---

## Alur Kerja Utama (4 Gate)

```
┌─────────────────────────────────────────────────┐
│ Gate 1: DELIVERABLE FORM                        │
│ → Tentukan bentuk akhir yang diinginkan         │
│ → APK? Modul LSPosed? RPC Service? Laporan?     │
├─────────────────────────────────────────────────┤
│ Gate 2: ENVIRONMENT TRUTH                       │
│ → Jalankan doctor.py dan preflight.py           │
│ → Ketahui apa yang bisa dan tidak bisa          │
├─────────────────────────────────────────────────┤
│ Gate 3: CODE LOCATION                           │
│ → Di mana kode target? DEX? Native? Dart?       │
│ → Apakah ada packer?                            │
├─────────────────────────────────────────────────┤
│ Gate 4: BASELINE & CONTROL                      │
│ → Buat control build (zero-change repack)       │
│ → Catat perilaku asli sebagai pembanding        │
└─────────────────────────────────────────────────┘
```

---

## Langkah-Langkah Praktis

### 1. Setup Awal
```bash
# Clone repository (jika belum)
git clone https://github.com/newliver666/apk-reverse.git
cd apk-reverse

# Jalankan setup otomatis
python setup.py

# Atau install manual
pip install -r requirements.txt
```

### 2. Periksa Lingkungan (Gate 2)
```bash
# Periksa semua tool dan kapabilitas
python apk_cli.py doctor

# Output JSON untuk integrasi
python apk_cli.py doctor --json

# Jika ada perangkat terhubung
python apk_cli.py doctor --device <serial>
```

### 3. Rekon Target (Gate 3)
```bash
# Rekon lengkap: fingerprint + string + lib mapping + validasi
python apk_cli.py recon --apk target.apk

# Atau langkah per langkah:
python apk_cli.py strings target.apk
python apk_cli.py strings target.apk --pattern "http"
```

### 4. Identifikasi (Gate 1 & 3)
Jawab 13 pertanyaan klasifikasi di `SKILL.md § Start here`:

| # | Pertanyaan Kunci |
|---|---|
| 1 | Apakah APK ini di-pack/hardened? |
| 2 | Di mana logika utama? (DEX / native / Flutter / server) |
| 3 | Apakah kode ada di plain dex? |
| 4 | Apa yang harus bisa dilakukan deliverable? |
| 5 | Apakah app memverifikasi signature sendiri? |
| 6 | Apa situasi device Anda? (rooted/emulator/tanpa device) |
| 7 | Arsitektur apa yang sebenarnya berjalan? |
| 8 | Apakah ada fitur spesifik yang gagal? |
| ... | (lihat SKILL.md untuk lengkapnya) |

### 5. Patching
```bash
# Patch byte-level (paling aman, tidak mengubah ukuran)
python apk_cli.py patch dex-bytes classes.dex \
    --offset 0x1234 --old-bytes "1200" --new-bytes "0e00"

# Patch string
python apk_cli.py patch dex-string classes.dex \
    --old-string "premium" --new-string "premium"

# Cari instruksi terlebih dahulu
python apk_cli.py patch find-insn classes.dex --method "checkLicense"
```

### 6. Repack & Sign
```bash
# Repack dengan signing otomatis
python apk_cli.py repack \
    --apk original.apk \
    --dex classes.dex=patched_classes.dex \
    --output patched.apk

# Repack tanpa signing (untuk pengujian)
python apk_cli.py repack \
    --apk original.apk \
    --dexdir work/dex/ \
    --output unsigned.apk \
    --no-sign
```

### 7. Verifikasi (Gate 4)
```bash
# Install, jalankan, dan ambil screenshot
python apk_cli.py verify --apk patched.apk

# Dengan serial perangkat tertentu
python apk_cli.py verify --apk patched.apk --serial <serial>
```

### 8. Generate Laporan
```bash
# Laporan Markdown
python apk_cli.py report --apk target.apk --format markdown --output report.md

# Laporan HTML (dark theme premium)
python apk_cli.py report --apk target.apk --format html --output report.html

# Semua format sekaligus
python apk_cli.py report --apk target.apk --format markdown --output report.md
```

### 9. Patching Khusus & Tool Otomasi

```bash
# Intersepsi HTTPS & Patch Network Security Config (NSC)
python apk_cli.py mitm --apk target.apk --inspect-only
python apk_cli.py mitm --export-frida ssl_unpin.js

# Debloat & Neuter Iklan/Telemetry di Manifest
python apk_cli.py debloat --target ./unpacked_apk --scan
python apk_cli.py debloat --target ./unpacked_apk --neuter

# Generator Script Frida (SSL Unpinning, Root Bypass, Crypto Sniffing)
python apk_cli.py frida-gen --template ssl-unpin --out bypass.js
python apk_cli.py frida-gen --template crypto-monitor --out crypto.js

# Inspeksi JNI & Auto-generate Frida Hook untuk .so
python apk_cli.py jni --so libnative.so --generate-hooks --out jni_hook.js
```

---

## Security Scanning

```bash
# Scan kebocoran data (WAJIB sebelum commit/publish)
python apk_cli.py scan leaks ./work

# Cek TLS/certificate pinning
python apk_cli.py scan tls target.apk

# Probe API endpoint
python apk_cli.py scan api target.apk

# Analisis signature verification
python apk_cli.py scan signatures target.apk
```

---

## Analisis Dinamis (Frida)

> ⚠️ Memerlukan perangkat rooted dengan frida-server terpasang

```bash
# Universal probe — melihat apa yang dilakukan app
python apk_cli.py frida probe com.target.app

# Spawn, patch di memori, lalu detach
python apk_cli.py frida spawn com.target.app --script hook.js

# RPC server — panggil fungsi target dari luar
python apk_cli.py frida rpc com.target.app --script rpc.js

# Execution trace dengan Stalker
python apk_cli.py frida stalker libtarget.so

# Scan DEX di memori (untuk APK yang di-pack)
python apk_cli.py frida mem-scan com.target.app
```

---

## Web Reverse Engineering

```bash
# Ekstrak kode sumber asli via Source Map (.js.map)
python apk_cli.py web sourcemap --url https://target.com/app.min.js --out-dir ./src_web

# Pindai interceptor Axios/Fetch, algoritma Crypto, dan endpoint API
python apk_cli.py web api-tracer --file ./src_web/app.bundle.js --json

# Deobfuskasi JavaScript, unpack p.a.c.k.e.r, decode escape hex, netralkan debugger
python apk_cli.py web deobf --file bundle.min.js --output bundle.clean.js

# Buat Tampermonkey Userscript (template: bypass-anti-debug, hook-api, dom-unlock, override-func)
python apk_cli.py web userscript --domain target.com --template bypass-anti-debug --output bypass.user.js

# Jalankan HTTP Map-Local Interceptor Proxy
python apk_cli.py web serve --port 8080 --map-local "/static/js/app.js=./bundle.clean.js"
```

---

## Aturan Penting (Jangan Dilanggar!)

1. **R1** — Tulis deliverable sebagai kalimat yang bisa diuji SEBELUM mulai kerja
2. **R2** — Ubah SATU variabel saja, dan selalu punya control build
3. **R3** — Jangan klaim selesai tanpa verifikasi langsung di device
4. **R4** — Identifikasi layer yang benar sebelum patching

### Two-Strike Rule
> Jika percobaan yang SAMA gagal **dua kali**, BERHENTI dan kembali ke klasifikasi.
> Jangan coba variasi ketiga — modelnya yang salah, bukan parameternya.

### Symptom Index
> Jika ada gejala yang cocok di tabel symptom index (di SKILL.md), BACA file
> referensi yang ditunjuk SEBELUM mencoba lagi. Setiap baris di sana adalah
> pelajaran yang sudah dibayar mahal.

---

## Referensi Cepat

| Topik | File |
|---|---|
| Rekon & identifikasi | `references/recon.md` |
| Patching DEX | `references/dex-patching.md` |
| Byte-level edit | `references/byte-level-patching.md` |
| Repack & sign | `references/repack-and-sign.md` |
| Verifikasi | `references/verification.md` |
| Anti-tamper | `references/native-tamper-and-suicide.md` |
| Frida & dinamis | `references/dynamic-frida.md` |
| TLS & cert | `references/tls-and-cert.md` |
| Packer | `references/packers.md` |
| Web Reverse Engineering | `references/web-reverse.md` |
| Kesalahan umum | `references/pitfalls.md` |
| Disiplin kerja | `references/long-task-discipline.md` |

---

## Tips untuk Pengguna Windows

1. **Path separator** — Gunakan `\\` atau `/` (Python menerima keduanya)
2. **PowerShell** — Beberapa tool perlu dijalankan di CMD jika PowerShell bermasalah
3. **Long path** — Aktifkan dukungan long path di Windows Registry jika path terlalu panjang
4. **adb** — Pastikan Android SDK Platform Tools ada di PATH
5. **Encoding** — Beberapa output mungkin perlu `chcp 65001` untuk UTF-8

---

> 💡 **Tip**: Gunakan `python apk_cli.py list` untuk melihat daftar lengkap semua skrip
> yang tersedia beserta penjelasannya.
