# Direct-to-Origin Discovery & Cloudflare Bypass Playbook

This playbook provides actionable, step-by-step methodologies to discover the genuine **Origin Web Server IP address** hidden behind Cloudflare reverse proxies.

Discovering the Origin IP allows you to bypass all Cloudflare WAF, IUAM, Turnstile, and rate-limiting defenses with **zero challenge delay** and **100% reliability**.

---

## 1. Direct-to-Origin Conceptual Overview

```
                                  [Target Domain: example.com]
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
     [Normal Cloudflare Route]                                     [Direct-to-Origin Route]
     https://example.com/                                          https://198.51.100.25/
     ├── Anycast IP: 104.21.42.100 (Cloudflare)                    ├── Unicast IP: 198.51.100.25 (Origin Server)
     ├── Layer 1–6 Deep Inspection                                 ├── Header -> Host: example.com
     ├── 5-Second IUAM Challenge / Turnstile                       ├── ZERO Cloudflare Inspection Active
     └── Rate Limiting Enforced                                    └── Response: 200 OK (Instantaneous)
```

When an Origin IP is used directly, traffic never traverses Cloudflare's Anycast network. Cloudflare's edge rules, challenge scripts, and firewalls are never invoked.

---

## 2. Discovery Vector 1: Subdomain Reconnaissance (Gray-Clouded Records)

Webmasters frequently configure subdomains for administrative or legacy services without enabling Cloudflare's orange-cloud proxy (leaving them "gray-clouded").

### High-Probability Subdomain Targets:
```
origin.example.com          direct.example.com          direct-connect.example.com
cpanel.example.com          whm.example.com             webmail.example.com
mail.example.com            smtp.example.com            mx.example.com
dev.example.com             development.example.com     staging.example.com
stage.example.com           test.example.com            beta.example.com
admin.example.com           portal.example.com          api-origin.example.com
origin-api.example.com      backend.example.com         internal.example.com
static.example.com          assets.example.com          img.example.com
vpn.example.com             ns1.example.com             ftp.example.com
```

### Automation via `cf_origin_finder.py`:
```bash
python scripts/cf_origin_finder.py --domain example.com --json
```

---

## 3. Discovery Vector 2: Certificate Transparency Logs (crt.sh & Censys)

All SSL/TLS certificates issued by public Certificate Authorities (Let's Encrypt, DigiCert, Sectigo) are published to public Certificate Transparency logs.

### Why CT Logs Leak Origins:
- Developers frequently issue a certificate for `*.example.com` or `origin.example.com` before placing the site behind Cloudflare.
- The CT log permanently records the historical Subject Alternative Names (SANs).

### Querying crt.sh Programmatically:
```python
import json
import urllib.request

def get_subdomains_from_crtsh(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    subdomains = set()
    with urllib.request.urlopen(req, timeout=15) as resp:
        records = json.loads(resp.read().decode('utf-8'))
        for r in records:
            for sub in r.get("name_value", "").split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and not sub.startswith("*"):
                    subdomains.add(sub)
    return subdomains
```

---

## 4. Discovery Vector 3: Favicon Hash Shodan / Censys Scanning

If the website hosts a unique favicon (`/favicon.ico`), calculating its **Murmur3 hash** allows searching global IPv4 Internet scan databases (Shodan, Censys, ZoomEye) for servers serving that exact icon—even if the IP has no DNS record attached.

### Computing Favicon Murmur3 Hash:
```python
import base64
import mmh3 # pip install mmh3
import urllib.request

def get_favicon_hash(url: str) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        favicon = resp.read()
    b64 = base64.encodebytes(favicon)
    return mmh3.hash(b64)

# Example Usage:
# fav_hash = get_favicon_hash("https://example.com/favicon.ico")
# Search Shodan: http.favicon.hash:<hash>
# Search Censys: services.http.response.favicons.md5_hash: <hash>
```

---

## 5. Discovery Vector 4: Mail Server (MX / SPF / Return-Path) Analysis

Email servers are rarely proxied through Cloudflare because Cloudflare's standard CDN only proxies HTTP/HTTPS (ports 80/443).

1. **Query MX Records:**
   ```bash
   nslookup -type=mx example.com
   ```
2. **Inspect SPF Record:**
   ```bash
   nslookup -type=txt example.com
   ```
   *Look for `v=spf1 ip4:198.51.100.0/24 include:... ~all`*. The `ip4:` range directly exposes the origin datacenter.
3. **Trigger Outbound Email:**
   Sign up for an account or trigger a password reset on `example.com`. Inspect the email headers in your inbox:
   ```
   Received: from web-origin-01.internal (198.51.100.25)
       by mail.example.com with ESMTP; Tue, 06 Oct 2026 02:20:00 +0000
   ```
   The `Received: from` header contains the real web server's outbound IP!

---

## 6. Discovery Vector 5: Outbound Webhook & SSRF Pingbacks

If the target web application has features that fetch remote URLs (e.g. "Import Profile Image from URL", "Webhook Settings", "PDF URL Generator"):

```
┌─────────────────────────┐          ┌───────────────────────────┐
│ Target Backend Server   │─────────►│ Your Controlled Server    │
│ (Hidden Origin IP)      │  HTTP    │ https://your-server.com/  │
└─────────────────────────┘          └─────────────┬─────────────┘
                                                   │ Logs Remote IP:
                                                   ▼
                                     [Remote IP: 198.51.100.25]
```

1. Enter your server's URL into the target's import/webhook input.
2. Monitor your server's access log (`tail -f /var/log/nginx/access.log`).
3. The incoming HTTP request's client IP is the **Origin Server IP**.

---

## 7. Origin Validation Protocol

Once a candidate IP address (e.g. `198.51.100.25`) is found, execute this validation check:

```bash
# 1. Send HTTPS request with Host header
curl -k -i -H "Host: example.com" https://198.51.100.25/

# 2. Check response headers:
# - Is 'cf-ray' MISSING? (Must be YES)
# - Is 'server: cloudflare' MISSING? (Must be YES)
# - Does the HTML title/body match the real website? (Must be YES)
```

### Direct Connection Automation in Python:
```python
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(
    "https://198.51.100.25/api/v1/posts",
    headers={
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/133.0.0.0 Safari/537.36"
    }
)

with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
    html = resp.read().decode('utf-8')
    print("Fetched Directly from Origin! Size:", len(html))
```
