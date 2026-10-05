# Changelog

> *Dimodifikasi dan disempurnakan oleh ALDY*

Semua perubahan penting pada proyek ini didokumentasikan di file ini.

Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/).
Proyek ini mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## [1.2.0] — 2026-10-05 (Modifikasi oleh ALDY)

### Ditambahkan
- **npx CLI Runner** (`bin/apk-reverse.js`) — Executable Node.js cross-platform untuk menjalankan seluruh toolkit via `npx apk-reverse <command>` tanpa instalasi manual
- **package.json** — Konfigurasi npm package untuk distribusi via npm registry dan `npx`
- **.npmignore** — Filter untuk mengecualikan cache/test saat packaging
- **Web Reverse Engineering** — 4 modul baru: `sourcemap_extractor.py`, `web_api_tracer.py`, `js_deobfuscator.py`, `web_modifier.py`
- **README.md** diperluas menjadi ~860 baris dengan dokumentasi komprehensif (Bahasa Indonesia)
- **Kredit modifikasi** ditambahkan ke seluruh file yang memiliki credit/authorship

## [1.1.0] — 2026-09-29

### Ditambahkan
- **Unified CLI** (`apk_cli.py`) — Satu titik masuk untuk semua 55+ skrip, dengan subcommand terorganisir:
  `doctor`, `recon`, `strings`, `patch`, `repack`, `verify`, `scan`, `frida`, `report`, `list`
- **Report Generator** (`scripts/report_generator.py`) — Menghasilkan laporan analisis APK dalam format:
  - Markdown (dengan tabel dan badge)
  - HTML (dark theme premium dengan glassmorphism)
  - JSON (untuk integrasi otomatis)
  - Mode `all` (ketiga format sekaligus)
- **Setup Script** (`setup.py`) — Skrip instalasi otomatis yang:
  - Memeriksa versi Python
  - Menginstall dependensi
  - Memeriksa tool-tool penting
  - Membuat direktori kerja
  - Menjalankan doctor.py untuk verifikasi
- **Requirements** (`requirements.txt`) — File dependensi Python lengkap, terorganisir per domain
- **Configuration Template** (`config.example.yaml`) — Template konfigurasi dengan komentar Bahasa Indonesia,
  mencakup lingkungan, perangkat, toolchain, signing, analisis, laporan, dan logging
- **Panduan Cepat** (`references/panduan-cepat.md`) — Panduan langkah-demi-langkah dalam Bahasa Indonesia:
  - Prasyarat dan setup
  - Alur kerja 4-gate dengan diagram
  - Perintah CLI untuk setiap tahap
  - Security scanning
  - Analisis dinamis Frida
  - Tips khusus Windows
- **README Indonesia** (`README.id.md`) — README lengkap dalam Bahasa Indonesia
- **Changelog** (`CHANGELOG.md`) — Pencatatan perubahan versi
- **Eval cases** tambahan — 4 kasus evaluasi baru (total 7) di `evals/evals.json`:
  - Kasus 4: Native library crash analysis
  - Kasus 5: Split APK handling
  - Kasus 6: Ad removal workflow
  - Kasus 7: Frida spawn-gating untuk APK yang di-pack
- **Integrasi Antigravity IDE** — Dokumentasi tentang cara menggunakan skill di Google Antigravity IDE

### Diperbaiki
- Evals sekarang memiliki asersi yang lebih spesifik dan terukur
- Penambahan 57 skrip ke katalog CLI (dari 55 sebelumnya)

### Catatan Migrasi
- Tidak ada breaking change dari v1.0
- File-file baru sepenuhnya opsional dan tidak mengubah SKILL.md atau skrip yang ada
- `config.yaml` hanya dibaca jika ada; tanpa file ini semua skrip tetap berjalan normal

## [1.0.0] — 2026-09-22

### Rilis Awal
- `SKILL.md` — Prosedur dengan 4 gate, 4 aturan override, symptom index, workflow 8 langkah
- 55 skrip Python/JS/Bash untuk analisis statis, dinamis, patching, repacking
- 44 dokumen referensi teknis
- 5 precedent case study
- Sistem eval (skeleton)
- Evidence & capability matrix
- CI/CD via GitHub Actions
