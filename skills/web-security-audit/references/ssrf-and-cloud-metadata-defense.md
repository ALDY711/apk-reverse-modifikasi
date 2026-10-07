# Server-Side Request Forgery (SSRF) & Cloud Metadata Defense

> Panduan komprehensif analisis, pengujian defensif, dan pengerasan arsitektur web terhadap kerentanan Server-Side Request Forgery (SSRF — OWASP A10:2021), eksfiltrasi kredensial instance cloud metadata (AWS, GCP, Azure), dan teknik mitigasi DNS Rebinding.

---

## 1. Anatomi & Vektor Serangan SSRF

Server-Side Request Forgery (SSRF) terjadi ketika aplikasi web mengambil sumber daya jarak jauh (*remote resource*) berdasarkan URL yang disediakan oleh pengguna tanpa melakukan validasi yang memadai terhadap alamat tujuan atau resolusi DNS:

```
+-----------------------------------------------------------------------------------+
| PENGGUNA EKSTERNAL                                                                |
| Request: POST /api/fetch-avatar                                                   |
| Body: {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}|
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| APLIKASI WEB (DMZ / CLOUD VM)                                                     |
| Mengabaikan validasi dan memanggil HTTP request ke IP tujuan internal...         |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| CLOUD METADATA SERVICE (INTERNAL IP: 169.254.169.254)                             |
| Menyajikan token IAM Role, private key, kubeconfig, atau data rahasia cloud!      |
+-----------------------------------------------------------------------------------+
```

### Fitur Web yang Sering Menjadi Titik Kerentanan:
1. **Webhook Integrations:** Pengiriman notifikasi event ke URL eksternal pelanggan.
2. **URL Preview & Link Scraping:** Menampilkan ringkasan OpenGraph dari tautan yang diposting.
3. **Konversi Dokumen / Generator PDF:** Pustaka seperti `wkhtmltopdf`, Headless Chrome / Puppeteer yang merender HTML berisi tag `<iframe src="...">` atau `<img src="...">`.
4. **File Import / Avatar Fetcher:** Fitur "Unggah dari URL".
5. **XML Parsers (XXE to SSRF):** Tag `<!ENTITY xxe SYSTEM "http://169.254.169.254/">`.

---

## 2. Katalog Endpoint Cloud Metadata Service

Jika penyerang berhasil memicu SSRF pada lingkungan cloud publik, target utama mereka adalah API metadata internal yang tidak memerlukan autentikasi login biasa:

| Cloud Provider | Alamat IP / Hostname Metadata | Endpoint Kritis (Kredensial & Secrets) |
|---|---|---|
| **Amazon Web Services (AWS)** | `http://169.254.169.254/` | `/latest/meta-data/iam/security-credentials/<role-name>`<br>`/latest/user-data/` |
| **Google Cloud Platform (GCP)** | `http://metadata.google.internal/`<br>`http://169.254.169.254/` | `/computeMetadata/v1/instance/service-accounts/default/token`<br>`/computeMetadata/v1/project/attributes/ssh-keys` |
| **Microsoft Azure** | `http://169.254.169.254/` | `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` |
| **Kubernetes (K8s)** | `https://kubernetes.default.svc/` | `/api/v1/namespaces/default/secrets`<br>`/var/run/secrets/kubernetes.io/serviceaccount/token` |
| **DigitalOcean** | `http://169.254.169.254/` | `/metadata/v1/id`<br>`/metadata/v1/user-data` |

---

## 3. Vektor Bypass & Obfuskasi Alamat IP

Validasi sederhana berbasis *blacklist* (seperti `if "127.0.0.1" in url`) sangat mudah ditembus menggunakan variasi representasi IP:

### A. Obfuskasi Format IP (Octal, Hex, Dword)
* **Dword Integer:** `http://2130706433/` $\rightarrow$ setara dengan `127.0.0.1`.
* **Octal Notation:** `http://0177.0.0.1/` atau `http://0177.0.0.01/` $\rightarrow$ `127.0.0.1`.
* **Hexadecimal:** `http://0x7f.0x0.0x0.0x1/` atau `http://0x7f000001/`.
* **Omission of Zeroes:** `http://127.1/` $\rightarrow$ dievaluasi kernel sebagai `127.0.0.1`.

### B. IPv6 & IPv4-Mapped IPv6
* `http://[::1]/` (IPv6 Loopback)
* `http://[::ffff:127.0.0.1]/` (IPv4-mapped IPv6)
* `http://[0:0:0:0:0:ffff:169.254.169.254]/` (IPv4-mapped AWS Metadata)

### C. DNS Rebinding (Time-of-Check to Time-of-Use / TOCTOU)
Aplikasi memvalidasi IP saat pemeriksaan pertama, namun melakukan permintaan HTTP sesungguhnya pada resolusi DNS kedua:
1. Penyerang mendaftarkan domain `rebind.attacker.com` dengan TTL = 0.
2. Saat validasi URL aplikasi: DNS menjawab `93.184.216.34` (IP publik sah $\rightarrow$ Lolos pengecekan).
3. Beberapa milidetik kemudian saat `curl` atau `requests.get()` dieksekusi: DNS menjawab `169.254.169.254` (IP metadata cloud).

---

## 4. Arsitektur Pertahanan Defensif (Hardening Recipes)

### 1. Migrasi AWS IMDSv2 (Session-Oriented Metadata)
Nonaktifkan IMDSv1 pada seluruh EC2 instance. IMDSv2 mewajibkan pembuatan token sesi via header `X-aws-ec2-metadata-token-ttl-seconds` dengan metode `PUT`:
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-endpoint enabled
```
Karena sebagian besar SSRF hanya mampu melakukan request `GET`, SSRF tidak dapat mengambil token IMDSv2.

### 2. Validasi Transport Tingkat Rendah (Safe HTTP Client Pattern)
Penyelesaian sejati untuk SSRF adalah **melakukan resolusi DNS secara mandiri, memvalidasi seluruh IP hasil resolusi terhadap daftar CIDR terlarang, lalu mengunci koneksi TCP langsung ke IP yang divalidasi** (*DNS Pinning*):

```python
import ipaddress
import socket
import urllib.parse
import requests

BLOCKED_CIDRS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-Local / AWS Metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-Local
]

def is_safe_ip(ip_str: str) -> bool:
    """Periksa apakah IP berada di rentang publik yang aman."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for blocked in BLOCKED_CIDRS:
            if ip in blocked:
                return False
        return True
    except ValueError:
        return False

def safe_fetch(url: str, timeout: int = 5):
    """Ambil URL dengan validasi IP sebelum koneksi (Anti-SSRF & Anti-DNS-Rebinding)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Protokol tidak diizinkan. Hanya HTTP dan HTTPS.")

    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # 1. Resolusi seluruh IP hostname
    resolved_ips = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for family, socktype, proto, canonname, sockaddr in resolved_ips:
        ip_addr = sockaddr[0]
        if not is_safe_ip(ip_addr):
            raise PermissionError(f"Akses ditolak: Host mengarah ke alamat privat/terlarang ({ip_addr})")

    # 2. Eksekusi request dengan redirect dimatikan untuk mencegah redirect-chain bypass
    return requests.get(url, allow_redirects=False, timeout=timeout)
```

### 3. Network Egress Firewall (iptables / AWS Security Groups)
Blokir paket keluar dari container/aplikasi menuju alamat link-local metadata pada tingkat sistem operasi:
```bash
# Blokir akses ke metadata service untuk pengguna aplikasi web (non-root):
iptables -A OUTPUT -m owner ! --uid-owner root -d 169.254.169.254 -j DROP
```

---

## 5. Checklist Verifikasi SSRF

- [ ] Pastikan seluruh pustaka HTTP tidak mengizinkan skema file berbahaya (`file://`, `gopher://`, `dict://`, `ftp://`).
- [ ] Nonaktifkan redirect otomatis (`allow_redirects=False`) pada klien HTTP internal untuk mencegah redirect chain ke metadata IP.
- [ ] Pastikan instance AWS menggunakan IMDSv2 (`http-tokens required`).
- [ ] Terapkan validasi IP DNS sebelum koneksi TCP dibuat (*pre-flight DNS check*).
- [ ] Pasang aturan egress firewall yang memblokir akses port 80/443 menuju `169.254.169.254` dari container web.
