---
name: api-security-graphql
description: "Audit and test API and GraphQL security, BOLA/IDOR authorization flaws, GraphQL introspection, query depth DoS, JWT vulnerabilities, and rate limiting."
---

# API Pentest & GraphQL Security Audit

> Toolkit dan panduan komprehensif untuk mengaudit, menganalisis, dan memvalidasi keamanan arsitektur API modern (RESTful, OpenAPI/Swagger, dan GraphQL). Meliputi pengujian celah BOLA (Broken Object Level Authorization / IDOR), GraphQL Introspection leakage, DoS kueri bersarang (Query Depth), audit manipulasi token JWT, serta pengujian Rate Limiting.

---

## 1. Arsitektur & Dimensi Keamanan REST vs GraphQL

```
+-------------------------------------------------------------------------------+
|                             CLIENT / FRONTEND                                 |
+-------------------------------------------------------------------------------+
         | (REST: Beragam Endpoint)                 | (GraphQL: Endpoint Tunggal /graphql)
         v                                          v
+-------------------------------+       +---------------------------------------+
|        RESTful API LAYER      |       |           GRAPHQL ENGINE              |
|  - GET /api/v1/users/{id}     |       |  - Introspection Query (__schema)     |
|  - POST /api/v1/checkout      |       |  - Query / Mutation / Subscription    |
|  - OpenAPI / Swagger Specs    |       |  - Field Resolvers & Batched Queries  |
+-------------------------------+       +---------------------------------------+
         |                                           |
         v                                           v
[ Audit: BOLA, BFLA, Missing Auth ]     [ Audit: Query Depth, Alias DoS, Schema ]
```

---

## 2. Alur Kerja Audit Keamanan API (4 Tahap)

### Tahap 1: Audit Skema & Introspeksi GraphQL
Analisis file skema GraphQL (`schema.json` atau `.graphql`) untuk menemukan field sensitif dan celah otorisasi:
```bash
# Audit skema GraphQL hasil introspeksi
python skills/api-security-graphql/scripts/graphql_schema_auditor.py --schema ./schema.json

# Output dalam format JSON untuk integrasi pipeline keamanan
python skills/api-security-graphql/scripts/graphql_schema_auditor.py --schema ./schema.json --json
```

### Tahap 2: Pengujian Kompleksitas & Query Depth DoS
Analisis query GraphQL untuk mencegah serangan *Denial of Service* via kueri melingkar atau berulang:
```bash
# Periksa kedalaman kueri dan potensi serangan batching / alias overload
python skills/api-security-graphql/scripts/graphql_query_analyzer.py --query query.gql --max-depth 5
```

### Tahap 3: Pemindaian Potensi BOLA / IDOR pada OpenAPI Specs
Pindai spesifikasi OpenAPI/Swagger untuk mendeteksi endpoint rentan BOLA:
```bash
# Pindai file openapi.json untuk endpoint ID tanpa skema otorisasi yang ketat
python skills/api-security-graphql/scripts/api_bola_auditor.py --spec openapi.json
```

### Tahap 4: Audit Keamanan Token JWT & Rate Limiting
Verifikasi integritas token JWT dan ketahanan endpoint terhadap brute-force:
```bash
# Audit token JWT untuk algoritma 'none', expiry, dan information leakage
python skills/api-security-graphql/scripts/jwt_security_checker.py --token "eyJhbGciOi..."

# Uji perlindungan rate limiting pada endpoint otentikasi
python skills/api-security-graphql/scripts/rate_limit_probe.py --url https://api.example.com/api/login --requests 30
```

---

## 3. Matriks Kerentanan OWASP API Security Top 10

| Kode | Kerentanan | Titik Bahaya | Solusi Mitigasi |
|---|---|---|---|
| **API1:2023** | **BOLA (IDOR)** | Endpoint resource menggunakan ID langsung (`/orders/{id}`) tanpa validasi kepemilikan | Terapkan validasi hak akses berbasis user token di setiap level resolver/controller. |
| **API2:2023** | **Broken Authentication** | Token JWT tanpa verifikasi signature, algoritma `none`, atau weak secret | Validasi signature ketat, gunakan algoritma asimetris (RS256/ES256). |
| **API3:2023** | **BOPLA (Object Property Level)** | Mass assignment pada JSON request body (`role: "admin"`) | Gunakan DTO / schema validation ketat; jangan terima field tidak terdaftar. |
| **API4:2023** | **Unrestricted Resource Consumption** | GraphQL nested queries tanpa depth limit atau ketiadaan Rate Limiting | Batasi Query Depth (maks 5–7), terapkan Query Cost Analysis dan Rate Limiting. |
| **API5:2023** | **BFLA (Function Level Auth)** | Akses endpoint administratif hanya dengan menebak URL (`/api/admin/users`) | Terapkan Role-Based Access Control (RBAC) ketat di gateway dan middleware. |
| **API8:2023** | **Security Misconfiguration** | GraphQL Introspection aktif di production; CORS terbuka ke semua origin | Matikan introspection di lingkungan production; batasi CORS Origin terpercaya. |

---

## 4. Panduan Referensi Teknis

- [OWASP API Top 10 Guide](references/owasp-api-top-10-guide.md): Panduan lengkap 10 kerentanan API modern beserta studi kasus pengujian dan mitigasinya.
- [GraphQL Security Hardening](references/graphql-security-hardening.md): Konfigurasi pengamanan server Apollo, Yoga, depth limiting, dan audit field suggestion.
- [JWT Security & Common Pitfalls](references/jwt-security-and-common-pitfalls.md): Analisis celah token JWT, Key Confusion (RS256 vs HS256), dan manajemen siklus hidup token.
- [API Testing Cheatsheet](references/api-testing-cheatsheet.md): Rangkuman praktis metode testing REST dan GraphQL untuk auditor keamanan.
