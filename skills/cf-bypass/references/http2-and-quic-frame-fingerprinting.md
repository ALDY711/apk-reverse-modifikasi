# HTTP/2 & HTTP/3 (QUIC) Frame-Level Fingerprinting Master Reference

This technical reference provides an exhaustive, byte-level analysis of Application-Layer Protocol Fingerprinting in **HTTP/2 (h2)** and **HTTP/3 (h3/QUIC)** as evaluated by Cloudflare Bot Management, Akamai, and AWS WAF.

---

## 1. The HTTP/2 Framing Architecture

In HTTP/2 (RFC 7540), all communication is split into binary frames multiplexed over a single TCP connection.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HTTP/2 Connection Handshake                     │
├────────────────────────────────────────────────────────────────────────┤
│ Client                                                          Server │
│   │─── 1. Magic Connection Preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)─►│
│   │─── 2. Initial SETTINGS Frame ─────────────────────────────────────►│
│   │─── 3. Initial WINDOW_UPDATE Frame ────────────────────────────────►│
│   │─── 4. PRIORITY Frames (Streams 3, 5, 7, 9, 11, 13) ───────────────►│
│   │─── 5. HEADERS Frame (Pseudo-headers: :method, :authority, etc.) ──►│
│   │                                                                    │
│   │◄── 6. Server SETTINGS Frame + ACK ─────────────────────────────────│
│   │◄── 7. Server HEADERS Response ─────────────────────────────────────│
└────────────────────────────────────────────────────────────────────────┘
```

Because different HTTP clients (Chrome, Safari, Firefox, cURL, Go, Python) send different parameter values, orders, and stream dependencies, Cloudflare constructs an immutable **HTTP/2 Fingerprint String**.

---

## 2. HTTP/2 Fingerprint Components (Akamai & Cloudflare Standard)

An HTTP/2 fingerprint is serialized into four distinct components separated by pipe `|` characters:

$$\text{H2 Fingerprint} = \text{SETTINGS}\;|\;\text{WINDOW\_UPDATE}\;|\;\text{PRIORITY}\;|\;\text{PSEUDO\_HEADERS}$$

```
Example Google Chrome 133 HTTP/2 Fingerprint:
1:65536,2:0,3:1000,4:6291456,6:262144|15663105|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,a,s,p
```

### Component 1: SETTINGS Parameters
Each parameter is represented as `ID:VALUE`:
- `1`: `SETTINGS_HEADER_TABLE_SIZE` (Chrome = `65536`, Go = `4096`)
- `2`: `SETTINGS_ENABLE_PUSH` (Chrome = `0`, Python urllib3 = `1`)
- `3`: `SETTINGS_MAX_CONCURRENT_STREAMS` (Chrome = `1000`)
- `4`: `SETTINGS_INITIAL_WINDOW_SIZE` (Chrome = `6291456`, cURL = `65535`)
- `5`: `SETTINGS_MAX_FRAME_SIZE` (Chrome = `16384`)
- `6`: `SETTINGS_MAX_HEADER_LIST_SIZE` (Chrome = `262144`)

### Component 2: Connection-Level WINDOW_UPDATE
Chrome immediately follows its `SETTINGS` frame with a `WINDOW_UPDATE` frame incrementing the connection flow-control window by `15663105` bytes (totaling `16777216` / 16MB).
Standard Python or Go libraries emit zero or default `65535` window updates.

### Component 3: Stream Priority Dependency Tree
Chrome defines a sophisticated stream priority tree with 6 default dependency nodes:
- `3:0:0:201`: Stream 3 depends on Stream 0, exclusive=0, weight=201 (HTML/JS)
- `5:0:0:101`: Stream 5 depends on Stream 0, exclusive=0, weight=101 (CSS)
- `7:0:0:1`: Stream 7 depends on Stream 0, exclusive=0, weight=1 (Images)
- `9:0:7:1`: Stream 9 depends on Stream 7, exclusive=0, weight=1
- `11:0:3:1`: Stream 11 depends on Stream 3, exclusive=0, weight=1
- `13:0:0:241`: Stream 13 depends on Stream 0, exclusive=0, weight=241 (Fonts)

Non-browser clients (such as Go `net/http2` or Python `httpx`) send **empty priority trees**, resulting in an instant bot signature flag.

### Component 4: Pseudo-Header Ordering
Browsers enforce a rigid pseudo-header transmission sequence:
- **Chrome:** `:method`, `:authority`, `:scheme`, `:path` (`m,a,s,p`)
- **Firefox:** `:method`, `:path`, `:authority`, `:scheme` (`m,p,a,s`)
- **Safari:** `:method`, `:scheme`, `:path`, `:authority` (`m,s,p,a`)
- **Python / Go:** Often send non-pseudo headers intermixed or in arbitrary order, violating RFC 7540 constraints.

---

## 3. HTTP/3 (QUIC) Transport Fingerprinting

HTTP/3 runs over UDP using the QUIC transport protocol (RFC 9000).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        QUIC Initial Packet Anatomy                     │
├────────────────────────────────────────────────────────────────────────┤
│ ├── Long Header (Type: Initial, Version: 0x00000001)                   │
│ ├── Destination / Source Connection IDs (DCID / SCID)                  │
│ ├── Token (Length + Data)                                              │
│ └── CRYPTO Frame (TLS 1.3 Client Hello encapsulated inside QUIC)       │
│      └── QUIC Transport Parameters Extension (0x39)                    │
│           ├── initial_max_data = 15728640                             │
│           ├── initial_max_stream_data_bidi_local = 6291456            │
│           ├── initial_max_stream_data_bidi_remote = 6291456           │
│           ├── initial_max_stream_data_uni = 6291456                   │
│           ├── initial_max_streams_bidi = 100                          │
│           ├── initial_max_streams_uni = 100                           │
│           ├── max_idle_timeout = 30000                                │
│           └── active_connection_id_limit = 8                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Differences Between Browser QUIC and Bot QUIC:
1. **Transport Parameters Extension Order:** Google Chrome serializes transport parameters in a fixed numerical and tag order.
2. **Datagram Packet Padding:** Browsers pad Initial QUIC UDP packets to exactly 1200 or 1250 bytes to prevent amplification attacks.
3. **Connection ID Entropy:** Browsers generate cryptographically secure pseudo-random 8-byte Connection IDs.

---

## 4. Bypassing HTTP/2 & HTTP/3 Fingerprint Inspection

| Library | HTTP/2 SETTINGS Match | Priority Tree Emulation | Pseudo-Header Ordering | Recommended Impersonation Flag |
|---|---|---|---|---|
| **Python `curl_cffi`** | **100% Match** | **100% Match** | **100% Match** | `impersonate="chrome133"` |
| **Node.js `got-scraping`**| **95% Match** | **90% Match** | **100% Match** | Default `gotScraping()` |
| **`curl-impersonate`** | **100% Match** | **100% Match** | **100% Match** | `curl_chrome133` |
| **Python `httpx` (h2)** | 20% (Mismatch) | 0% (None sent) | 50% (Variable) | NOT RECOMMENDED FOR WAF |
| **Python `requests`** | N/A (HTTP/1.1) | N/A | N/A | NOT RECOMMENDED FOR WAF |

### Testing Your H2 Fingerprint via CLI:
```bash
# Test HTTP/2 frame signatures against fingerprint mirrors
python -c '
from curl_cffi import requests
resp = requests.get("https://tls.browserleaks.com/json", impersonate="chrome133")
print("HTTP Version:", resp.json().get("http_version"))
print("JA3 Hash:", resp.json().get("ja3_hash"))
'
```
