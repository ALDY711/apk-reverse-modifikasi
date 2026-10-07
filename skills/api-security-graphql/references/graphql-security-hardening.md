# GraphQL Security Hardening & Best Practices

> Panduan komprehensif untuk mengamankan server GraphQL (Apollo Server, GraphQL Yoga, Helix) dari serangan DoS, kebocoran introspeksi, dan eksploitasi otorisasi.

---

## 1. Mematikan Introspection di Lingkungan Produksi

### Masalah
Secara default, kueri introspeksi (`__schema`, `__type`) memungkinkan siapa saja mengekstrak seluruh skema backend, termasuk query privat, mutasi administratif, dan tipe internal.

### Solusi pada Apollo Server v4:
```javascript
import { ApolloServer } from '@apollo/server';
import { ApolloServerPluginLandingPageDisabled } from '@apollo/server/plugin/disabled';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Matikan di produksi
  plugins: process.env.NODE_ENV === 'production' 
    ? [ApolloServerPluginLandingPageDisabled()] 
    : []
});
```

---

## 2. Membatasi Kedalaman Kueri (Query Depth Limiting)

### Masalah
Hubungan bersarang antar relasi memungkinkan penyerang membuat kueri eksponensial:
```graphql
query maliciousQuery {
  user {
    posts {
      author {
        posts {
          author {
            posts {
              # Mengakibatkan ratusan query database & memory overflow
            }
          }
        }
      }
    }
  }
}
```

### Solusi:
Gunakan pustaka validasi kedalaman seperti `graphql-depth-limit`:
```javascript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)] // Maksimal kedalaman kueri = 5 tingkat
});
```

---

## 3. Mitigasi Batching Attack & Alias Overloading

### Masalah
Penyerang dapat membungkus ratusan operasi ke dalam satu permintaan HTTP POST dengan menggunakan alias:
```graphql
mutation bruteForcePin {
  try0001: verifyPin(pin: "0001") { success }
  try0002: verifyPin(pin: "0002") { success }
  try0003: verifyPin(pin: "0003") { success }
}
```

### Solusi:
1. Batasi jumlah alias per kueri (maksimal 5–10).
2. Terapkan *Query Cost Analysis* via `graphql-cost-analysis`.
3. Terapkan Rate Limiting pada tingkat resolver mutasi sensitif.
