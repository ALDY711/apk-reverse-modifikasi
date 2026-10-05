# Manifest Neutering: Teori & Implementasi

## Mengapa Manifest Neutering Lebih Aman daripada Hapus Bytecode?

Dalam arsitektur Android OS, komponen aplikasi (`Activity`, `Service`, `BroadcastReceiver`, `ContentProvider`) dikelola langsung oleh sistem via `PackageManagerService` dan `ActivityManagerService`.

### Keuntungan Manifest Neutering
1. **Zero ClassNotFoundException**: Kelas Java SDK tetap ada di dalam DEX, sehingga inisialisasi kode aplikasi atau refleksi tidak akan memicu crash fatal.
2. **OS Menolak Peluncuran**: Dengan menambahkan `android:enabled="false"` dan `android:exported="false"` pada tag manifest:
   - Sistem operasi tidak akan pernah meluncurkan Activity iklan (dialog pop-up / full screen).
   - Receiver atribusi iklan tidak akan pernah menerima broadcast `BOOT_COMPLETED` atau `INSTALL_REFERRER`.
   - Service latar belakang tidak akan pernah dialokasikan memori oleh Android OS.
3. **Penghematan Baterai & Data**: Komponen latar belakang tidak aktif sehingga konsumsi baterai dan jaringan berkurang drastis.

Gunakan tool `scripts/debloat_manifest.py` untuk melakukan neutering otomatis, dan gunakan `scripts/ad_stub_gen.py` jika aplikasi mewajibkan tontonan iklan untuk membuka fitur tertentu.
