# OWASP API Security Top 10 (2023 Edition) Comprehensive Guide

> Panduan mendalam tentang taksonomi kerentanan API modern, skenario eksploitasi defensif, dan arsitektur pengerasan backend.

---

## 1. Daftar Lengkap OWASP API Security Top 10

```
+-------------------------------------------------------------------------------+
|                        OWASP API SECURITY TOP 10 (2023)                       |
+-------------------------------------------------------------------------------+
| API1:2023 | Broken Object Level Authorization (BOLA / IDOR)                  |
| API2:2023 | Broken Authentication (Credential Stuffing, Weak Tokens)          |
| API3:2023 | Broken Object Property Level Authorization (BOPLA)               |
| API4:2023 | Unrestricted Resource Consumption (DoS, Missing Rate Limits)     |
| API5:2023 | Broken Function Level Authorization (BFLA, Privilege Escalation) |
| API6:2023 | Unrestricted Access to Sensitive Business Flows                  |
| API7:2023 | Server-Side Request Forgery (SSRF)                               |
| API8:2023 | Security Misconfiguration (CORS, Debug Info, Introspection)      |
| API9:2023 | Improper Inventory Management (Zombies, Shadow APIs)              |
| API10:2023| Unsafe Consumption of APIs (Untrusted Third-Party Webhooks)       |
+-------------------------------------------------------------------------------+
```

---

## 2. API1:2023 - Broken Object Level Authorization (BOLA)

### Mengapa Terjadi?
Backend menerima ID objek dari parameter URL (misalnya `/api/v1/invoices/10492`) tanpa memvalidasi apakah pengguna yang sedang login (`req.user.id`) memiliki hak milik atas faktur `10492`.

### Remediasi Defensif
Gunakan filter kepemilikan berbasis database context:
```python
# CONTOH DEFENSIVE FLASK / SQLALCHEMY:
@app.route("/api/v1/invoices/<int:invoice_id>", methods=["GET"])
@jwt_required()
def get_invoice(invoice_id):
    current_user_id = get_jwt_identity()
    # Pastikan query SELALU mengunci user_id pemilik:
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user_id).first()
    if not invoice:
        abort(404) # Gunakan 404 bukan 403 untuk mencegah user-enumeration
    return jsonify(invoice.to_dict())
```

---

## 3. API3:2023 - Broken Object Property Level Authorization (BOPLA)

### Mengapa Terjadi?
Terkenal dengan sebutan *Mass Assignment* atau *Over-Posting*. Klien mengirim payload JSON dengan atribut tambahan seperti `{ "name": "Budi", "role": "admin", "is_verified": true }`, dan backend langsung mem-binding seluruh objek ke model database:
`user.update(request.json)`

### Remediasi Defensif
Gunakan skema Data Transfer Object (DTO) ketat via Pydantic / Zod / Joi:
```python
from pydantic import BaseModel, Field

class UserProfileUpdateDTO(BaseModel):
    name: str = Field(..., max_length=100)
    avatar_url: str | None = None
    # JANGAN CANTUMKAN role atau is_verified di sini!
```
