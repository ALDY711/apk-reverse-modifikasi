# TLS Fingerprinting & JA4 Suite Master Reference

This document explains the cryptographic, transport, and application-layer fingerprinting algorithms used by Cloudflare and modern Web Application Firewalls (WAFs) to detect automated HTTP clients.

---

## 1. The TLS Handshake & Client Hello Mechanics

During an HTTPS connection, the client and server exchange unencrypted handshake packets to negotiate cryptographic keys before application data flows.

```
Client                                                  Server
  │                                                       │
  │─── 1. TLS Client Hello ──────────────────────────────►│
  │    (TLS Version, Cipher Suites, Extensions,           │
  │     Supported Groups, ALPN, Signature Algorithms)     │
  │                                                       │
  │◄── 2. TLS Server Hello + Certificate + Key Exchange ──│
  │                                                       │
  │─── 3. Client Key Exchange + Finished ────────────────►│
  │                                                       │
  │◄── 4. Encrypted Application Data (HTTP/2 or HTTP/3) ──►│
```

Because different operating systems, cryptographic libraries (OpenSSL, BoringSSL, NSS, CryptoAPI), and browsers construct the `Client Hello` packet differently, the packet serves as an immutable **client fingerprint**.

---

## 2. JA3 & JA3S Fingerprinting Architecture

Developed by Salesforce engineers in 2017, JA3 concatenates 5 specific fields from the `Client Hello` packet with commas `,` and dashes `-`, then computes the MD5 hash of the string:

$$\text{JA3 String} = \text{SSLVersion},\text{Ciphers},\text{Extensions},\text{EllipticCurves},\text{EllipticCurvePointFormats}$$

### Example JA3 Construction:
```
Raw String: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0
MD5 Hash (JA3): 8a6797a7605d8f3e5860d5b4a90059bf (Google Chrome 133 on Windows)
```

### Why Standard Python `requests` Fails:
Python's `requests` library relies on Python's native `ssl` module, which binds to standard system OpenSSL:
- OpenSSL sorts cipher suites alphabetically by default.
- OpenSSL omits browser-specific extensions like GREASE (Generate Random Extensions And Sustain Extensibility) and Application-Layer Protocol Negotiation (ALPN: `h2`, `http/1.1`).
- Cloudflare identifies the JA3 hash as `Python-urllib` or `OpenSSL-Generic` and issues an instant 403 Forbidden.

---

## 3. The Modern JA4 Suite (JA4, JA4H, JA4T, JA4S)

Created by John Althouse in 2023, JA4 replaces JA3 with a human-readable, multi-protocol suite that is immune to permutation and GREASE attacks.

```
JA4 Fingerprint Format:
[Protocol][TLS Version][SNI][Cipher Count][Extension Count][ALPN]_[Sorted Cipher Hash]_[Sorted Extension Hash]

Example (Google Chrome 133):
t13d1516h2_8daaf6152771_b17853aa6725
```

### Detailed JA4 Component Breakdown:

| Section | Value | Meaning |
|---|---|---|
| `t` | Transport Protocol | `t` = TCP, `q` = QUIC (HTTP/3) |
| `13` | TLS Version | `13` = TLS 1.3, `12` = TLS 1.2, `10` = TLS 1.0 |
| `d` | SNI Indicator | `d` = Domain name present in SNI, `i` = IP address in SNI |
| `15` | Cipher Suite Count | Number of supported cipher suites offered (2 digits) |
| `16` | Extension Count | Number of TLS extensions offered (2 digits) |
| `h2` | First ALPN Value | `h2` = HTTP/2, `h3` = HTTP/3, `00` = No ALPN |
| `8daaf6152771` | Cipher Hash | Truncated SHA-256 (12 chars) of sorted cipher IDs |
| `b17853aa6725` | Extension Hash | Truncated SHA-256 (12 chars) of sorted extension IDs |

---

## 4. JA4H: HTTP Client Request Fingerprinting

JA4H analyzes the application-layer HTTP/1.1 and HTTP/2 headers:

$$\text{JA4H} = \text{[Method][Version][Cookie][Referer]}\text{\_}\text{[Header Count]}\text{\_}\text{[Sorted Header Hash]}\text{\_}\text{[Language Hash]}$$

```
Example Chrome 133 JA4H:
ge11cn11_35b6a7183e92_d41d8cd98f00_000000000000
```
- `ge`: `GET` method.
- `11`: HTTP/1.1 (or `20` for HTTP/2).
- `c`: Cookie header present (`n` = no cookie).
- `r`: Referer header present (`n` = no referer).
- `11`: 11 headers sent.
- `35b6a7183e92`: Hash of header names in their transmitted order.

If a script claims to be Chrome but sends headers in alphabetical order (e.g. `Accept`, `Authorization`, `User-Agent`), JA4H immediately catches the anomaly.

---

## 5. JA4T: TCP Stack Initial SYN Fingerprinting

JA4T measures the transport layer:
$$\text{JA4T} = \text{[Window Size]}\text{\_}\text{[TCP Options Order]}\text{\_}\text{[MSS]}\text{\_}\text{[Window Scale]}$$

```
Example Windows 10/11 TCP SYN:
64240_2-4-8-1-3_1460_8

Example Linux Ubuntu 24.04 TCP SYN:
29200_2-4-8-1-3_1460_7
```

If your `User-Agent` string specifies `Windows NT 10.0`, but Cloudflare's edge packet filter receives a TCP Window Size of `29200` with Scale factor `7` (Linux default), the JA4T score flags an **Operating System Mismatch**.

---

## 6. HTTP Client Fingerprint Comparison Matrix

| Client / Library | Engine / TLS Stack | JA3 Match Chrome? | JA4 Match Chrome? | HTTP/2 Frames Match? | Cloudflare Pass Rate |
|---|---|---|---|---|---|
| **Google Chrome 133** | Chromium BoringSSL | **YES (Original)** | **YES (Original)** | **YES (Original)** | **100%** |
| **Python `requests`** | OpenSSL 3.x | NO (Mismatch) | NO | NO (HTTP/1.1 only) | **0% – 5%** |
| **Node.js `axios`** | Node.js TLS (OpenSSL) | NO (Mismatch) | NO | NO | **5% – 15%** |
| **Go `net/http`** | Go crypto/tls | NO (Mismatch) | NO | NO (Go SETTINGS) | **0% – 5%** |
| **`got-scraping` (Node)** | Patched Node OpenSSL | **YES (Emulated)** | **YES (Emulated)** | **YES (Emulated)** | **85% – 92%** |
| **`curl_cffi` (Python)** | Patched libcurl | **YES (Bit-for-bit)** | **YES (Bit-for-bit)**| **YES (Bit-for-bit)**| **92% – 98%** |
| **Camoufox (Python)** | Firefox C++ Engine | **YES (Firefox JA4)**| **YES (Firefox JA4)**| **YES (Firefox)** | **96% – 99%** |

---

## 7. Configuration Guide for Perfect Fingerprint Matching

### In Python (`curl_cffi`):
```python
from curl_cffi import requests

session = requests.Session(impersonate="chrome133")
response = session.get(
    "https://tls.browserleaks.com/json",
    headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
    }
)
print("JA3 Text:", response.json().get("ja3_text"))
print("JA3 Hash:", response.json().get("ja3_hash"))
```

### In Node.js (`got-scraping`):
```typescript
import { gotScraping } from "got-scraping";

const res = await gotScraping({
  url: "https://tls.browserleaks.com/json",
  headerGeneratorOptions: {
    browsers: [{ name: "chrome", minVersion: 130, maxVersion: 136 }],
    devices: ["desktop"],
    locales: ["en-US", "en"],
    operatingSystems: ["windows"],
  },
});
console.log("TLS Fingerprint Result:", JSON.parse(res.body));
```
