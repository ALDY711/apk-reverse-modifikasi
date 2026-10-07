# Bedah Internal APK & Smali Surgery (Deep Internals Modification)

Panduan ini mendokumentasikan teknik rekayasa balik dan modifikasi aplikasi Android hingga ke lapisan terdalam: dari manipulasi bytecode Dalvik/ART (Smali), struktur Multi-DEX, pustaka native C/C++ (`.so`), hingga injeksi konfigurasi tingkat biner.

---

## 1. Anatomi Berkas DEX (Dalvik Executable)

Setiap file `.dex` di dalam APK memiliki struktur data biner yang ketat:

```text
+-----------------------+
|      DEX Header       | -> Magic, Checksum (Adler32), Signature (SHA-1), File Size
+-----------------------+
|      String IDs       | -> Offset ke string_data_item (panjang ULEB128 + UTF-8)
+-----------------------+
|       Type IDs        | -> Index ke descriptor tipe (misal: "Ljava/lang/String;")
+-----------------------+
|       Proto IDs       | -> Return type & parameter list methods
+-----------------------+
|       Field IDs       | -> Class, Type, Name untuk fields
+-----------------------+
|      Method IDs       | -> Class, Proto, Name untuk methods
+-----------------------+
|      Class Defs       | -> Access flags, Superclass, Interfaces, Class Data
+-----------------------+
|      Data Section     | -> Code items (instruksi bytecode), debug info, strings
+-----------------------+
```

### Aturan Emas Header Integritas:
Jika ada 1 byte saja di Data Section yang diubah secara biner:
1. Hitung ulang **SHA-1 Signature** (20 byte) dari offset `0x20` (32) sampai akhir file. Tulis hasilnya di offset `0x0C` (12-31).
2. Hitung ulang **Adler32 Checksum** (4 byte) dari offset `0x0C` (12) sampai akhir file. Tulis hasilnya di offset `0x08` (8-11).
3. **Urutan tidak boleh terbalik**, karena Adler32 memeriksa byte signature SHA-1!

---

## 2. Bedah Smali: Pola Modifikasi Logika Populer

### A. Membalikkan Kondisi Validasi (*Logic Inversion*)
Untuk melewati verifikasi lisensi, status login, atau cek root:

```smali
# KODE ASLI:
invoke-virtual {p0}, Lcom/example/Auth;->isSubscribed()Z
move-result v0
if-eqz v0, :cond_denied    # Jika v0 == 0 (false), lompat ke :cond_denied

# METODE MODIFIKASI 1 (Balik Cabang):
if-nez v0, :cond_denied    # Diubah menjadi if-nez (jika true lompat, false lanjut)

# METODE MODIFIKASI 2 (Force True via Konstanta):
const/4 v0, 0x1            # Paksa v0 = 1 (true)
if-eqz v0, :cond_denied

# METODE MODIFIKASI 3 (Ganti ke NOP atau GOTO):
goto :cond_approved        # Langsung lompat ke blok yang diizinkan
```

### B. Pembajakan Return Value Method (*Return Hijacking*)
Mengharuskan method selalu mengembalikan status sukses:

```smali
# 1. Mengembalikan Boolean True (1):
.method public isPremiumUser()Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method

# 2. Mengembalikan Angka 0 (Success Code):
.method public checkSecurityToken()I
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

# 3. Menetralkan Method Void (No-op):
.method public showInterstitialAd()V
    .registers 1
    return-void
.end method

# 4. Mengembalikan Object String Kustom:
.method public getAccountTier()Ljava/lang/String;
    .registers 2
    const-string v0, "VIP_UNLIMITED"
    return-object v0
.end method
```

### C. Alokasi Register & Keselamatan Stack Frame
Saat menyisipkan instruksi baru ke dalam method smali:
- Periksa `.registers N` atau `.locals N` di awal method.
- Jangan gunakan register yang sedang memegang variabel penting untuk operasi berikutnya.
- Jika kehabisan register lokal, naikkan jumlah `.locals` di header method, tetapi **perhatikan register parameter (`p0`, `p1`, dst.)** karena nomor register parameter akan bergeser jika `.registers` diubah tanpa hati-hati.

---

## 3. Patching Byte-Level Tanpa Smali Round-Trip (`dex_strpatch.py`)

Kompilasi ulang seluruh pohon smali (*smali round-trip*) pada aplikasi besar (>100 MB) berisiko merusak struktur R8 / ProGuard (`IncompatibleClassChangeError`).

**Solusi Bedah Sama Panjang (*Equal-Length Byte Patch*)**:
1. Targetkan string konstan di dalam DEX (misalnya URL API, kunci fitur, atau string boolean).
2. Ganti string tersebut dengan string baru yang memiliki **panjang byte UTF-8 persis sama**:
   ```powershell
   python skills/apk-reverse/scripts/dex_strpatch.py classes.dex classes_patched.dex "https://api.old.com" "https://api.new.com"
   ```
3. Keuntungan:
   - Prefix panjang ULEB128 tidak bergeser.
   - Seluruh offset `string_ids`, `type_ids`, dan `method_ids` tetap 100% utuh.
   - Header SHA-1 dan Adler32 dihitung ulang otomatis.
   - Waktu eksekusi: < 1 detik.

---

## 4. Bedah Pustaka Native C/C++ (`.so` / ARM64 Surgery)

Banyak aplikasi memindahkan verifikasi kritis ke pustaka C/C++ (`libnative.so`).

### A. Instruksi Kunci Arsitektur ARM64 (AArch64)
| Kode Hex Little-Endian | Assembler ARM64 | Efek |
|---|---|---|
| `1F 20 03 D5` | `NOP` | Tidak melakukan apa-apa (*skip check*). |
| `20 00 80 D2 C0 03 5F D6` | `MOV X0, #1; RET` | Mengembalikan angka 1 (true) dan return. |
| `00 00 80 D2 C0 03 5F D6` | `MOV X0, #0; RET` | Mengembalikan angka 0 (sukses) dan return. |
| `C0 03 5F D6` | `RET` | Langsung keluar dari fungsi (void). |

### B. Menetralkan Panggilan Bunuh Diri (*Suicide/Exit Calls*)
Jangan pernah menimpa fungsi `exit()` atau `abort()` dengan loop tak terhingga (`B .`), karena aplikasi akan membeku (*freeze*) dan mengunci thread mutex.
👉 **Ganti pemanggilnya** agar tidak pernah mengeksekusi cabang terminasi, atau ganti fungsi terminasi dengan `RET` biasa.

---

## 5. Injeksi Pra-Konfigurasi Database & SharedPreferences

Agar modifikasi menyertakan data bawaan saat pertama kali dipasang di HP:

### A. Pola Assets Pre-seed
1. Simpan database SQLite default di `assets/default_database.db`.
2. Di kelas `Application` atau Splash Activity smali, sisipkan kode penyalin file dari `getAssets().open("default_database.db")` ke `/data/data/<pkg>/databases/<dbname>.db` jika file target belum ada.

### B. Pola Direct SharedPreferences
1. Simpan preferensi XML di `assets/default_preferences.xml`.
2. Gunakan `SharedPreferences.Editor` saat startup untuk memuat preferensi awal secara otomatis.
