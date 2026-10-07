# IDOR & Broken Object Level Authorization (BOLA) Hardening Guide

Panduan teknis defensif komprehensif untuk mengidentifikasi, mengaudit, dan mengeraskan sistem kendali akses (*access control*) terhadap kerentanan **Insecure Direct Object Reference (IDOR)** dan **Broken Object Level Authorization (BOLA — OWASP API1:2023)** pada aplikasi web dan REST API.

---

## 1. Model Mental & Taksonomi IDOR / BOLA

IDOR/BOLA terjadi ketika aplikasi web atau API menerima parameter identitas objek (seperti `id`, `uuid`, `order_no`, atau `account_id`) dari pengguna dan mengakses langsung rekaman basis data tersebut tanpa memvalidasi apakah pengguna yang sedang login memiliki hak akses atas objek tersebut.

```
[Pengguna A (Login sebagai User ID: 101)]
                 │
                 ▼
[Kirim Permintaan HTTP] ──► GET /api/v1/invoices/9999  (Milik User ID: 202)
                 │
                 ▼
[Backend Controller]
  ❌ VULNERABLE:  Invoice::findOrFail($id) ────────────► Data User B Bocor! (HTTP 200)
  ✅ HARDENED:    Auth::user()->invoices()->find($id) ─► Akses Ditolak!   (HTTP 404/403)
```

---

## 2. Vektor Kerentanan Umum

### A. Pengambilan Data Telanjang via Primary Key
Pengembang mengambil data langsung dengan metode `find()`, `findById()`, atau `get_object_or_404()` tanpa menambahkan filter kepemilikan tenant:
```php
// RENTAN BOLA / IDOR
public function show($id) {
    $order = Order::findOrFail($id);
    return response()->json($order);
}
```
Penyerang cukup mengubah parameter ID di URL (`/orders/1`, `/orders/2`, `/orders/3`) untuk mengunduh seluruh transaksi pengguna lain.

### B. Modifikasi & Penghapusan Objek Tanpa Gate
Operasi mutasi data (UPDATE, PUT, DELETE) yang langsung mengandalkan ID dari rute:
```javascript
// RENTAN BOLA (Node.js Express)
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    await Document.findByIdAndDelete(req.params.id); // Dokumen milik siapapun terhapus!
    res.json({ success: true });
});
```

### C. Enumerasi Integer Auto-Increment
Penggunaan primary key berurutan (`1, 2, 3...`) mempermudah penyerang melakukan pemindaian otomatis (*mass scraping*) pada seluruh basis data.

---

## 3. Strategi Pengerasan & Remediasi Defensif

### Strategi 1: Tenant-Scoped Query Pattern (Solusi Utama)
Jangan pernah mengeksekusi query langsung dari model global. Selalu mulai pencarian dari relasi pengguna yang sedang aktif:

**PHP / Laravel:**
```php
// AMAN: Terisolasi pada koleksi user yang terautentikasi
public function show($id) {
    $order = auth()->user()->orders()->findOrFail($id);
    return response()->json($order);
}
```

**Node.js (Prisma / Mongoose):**
```javascript
// AMAN: Selalu sertakan userId dari token sesi
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    const order = await prisma.order.findFirst({
        where: {
            id: req.params.id,
            userId: req.user.id // Enforce kepemilikan
        }
    });

    if (!order) {
        return res.status(404).json({ error: 'Order tidak ditemukan.' });
    }
    return res.json(order);
});
```

**Python (FastAPI & SQLAlchemy):**
```python
# AMAN: Filter ganda pada primary key dan tenant owner
@router.get("/documents/{doc_id}")
def get_document(doc_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    doc = db.query(Document).filter(
        Document.id == doc_id,
        Document.owner_id == current_user.id
    ).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan.")
    return doc
```

---

### Strategi 2: Penerapan Policy & Gate Terpusat
Untuk alur bisnis kompleks (misalnya ketika objek dapat dibagikan kepada kolaborator atau manajer), gunakan layer otorisasi formal:

```php
// Di Laravel Controller:
public function update(Request $request, Invoice $invoice) {
    $this->authorize('update', $invoice); // Memanggil InvoicePolicy
    $invoice->update($request->validated());
    return response()->json($invoice);
}

// Di InvoicePolicy.php:
public function update(User $user, Invoice $invoice): bool {
    return $user->id === $invoice->user_id || $user->hasRole('admin');
}
```

---

### Strategi 3: Penggunaan UUID v7 atau NanoID (Opaque Identifiers)
Ganti sequential integer auto-increment pada URL publik dengan pengenal acak atau berbasis waktu:
* **UUID v7**: Menggabungkan timestamp Unix dengan keacakan kriptografis (indeks database tetap efisien, namun nilai tidak dapat ditebak penyerang).
* Contoh URL Aman: `/api/v1/invoices/018e3a2b-8b5a-7f12-a1b2-9f8e7d6c5b4a`.

---

### Strategi 4: Global Scopes pada Model ORM
Otomatisasi filter penyewa di tingkat model agar pengembang tidak lupa menyematkan filter `user_id`:
```php
// Laravel Model Global Scope
protected static function booted() {
    static::addGlobalScope('user_tenancy', function (Builder $builder) {
        if (auth()->check()) {
            $builder->where('user_id', auth()->id());
        }
    });
}
```

---

## 4. Matriks Pengujian Otorisasi Otomatis

Setiap endpoint yang menerima ID objek wajib diuji dengan skenario lintas-pengguna (*cross-tenant test*):

```php
// Test Otomatis (PHPUnit / Pest):
public function test_user_cannot_view_another_users_order() {
    $userA = User::factory()->create();
    $userB = User::factory()->create();
    $orderB = Order::factory()->create(['user_id' => $userB->id]);

    $response = $this->actingAs($userA)->getJson("/api/orders/{$orderB->id}");

    // Wajib mengembalikan 403 Forbidden atau 404 Not Found
    $response->assertStatus(404);
}
```
