# OWASP Secure Headers & Defensive Web Hardening Guide

This reference guide provides in-depth technical specifications and deployment recipes for HTTP response security headers recommended by the **OWASP Secure Headers Project**.

---

## 1. Summary of Standard Defensive Security Headers

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HTTP Security Headers Matrix                    │
├───────────────────────────────┬──────────────────────────┬─────────────┤
│ Header Name                   │ Primary Defensive Role   │ OWASP Rank  │
├───────────────────────────────┼──────────────────────────┼─────────────┤
│ **Content-Security-Policy**   │ XSS & Data Injection     │ CRITICAL    │
│ **Strict-Transport-Security** │ SSL Stripping / MitM     │ HIGH        │
│ **X-Frame-Options**           │ Clickjacking Defense     │ HIGH        │
│ **X-Content-Type-Options**    │ MIME-Type Confusion      │ MEDIUM      │
│ **Referrer-Policy**           │ URL / Token Leakage      │ MEDIUM      │
│ **Permissions-Policy**        │ Hardware API Restriction │ LOW         │
└───────────────────────────────┴──────────────────────────┴─────────────┘
```

---

## 2. Content-Security-Policy (CSP) Architecture

Content-Security-Policy is the single most powerful defense against Cross-Site Scripting (XSS). It instructs the browser to restrict which origins can execute scripts, load stylesheets, or open network connections.

### Recommended Baseline Policy:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'self';
```

### Key Directives:
- `default-src 'self'`: Fallback for all resource types. Only resources from the origin domain are permitted.
- `script-src 'self'`: Prevents inline `<script>` tags and untrusted external script injection unless explicitly allowed.
- `frame-ancestors 'self'`: Modern replacement for `X-Frame-Options`. Disallows loading the site inside unauthorized iframes.
- `object-src 'none'`: Disallows execution of legacy Flash/Java plugins.

---

## 3. Strict-Transport-Security (HSTS) Architecture

HSTS ensures that a user's browser never communicates with your server over unencrypted HTTP:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age=31536000`: Enforces HTTPS for 1 full year (31,536,000 seconds).
- `includeSubDomains`: Extends the HTTPS requirement to all subdomains (e.g. `api.example.com`, `admin.example.com`).
- `preload`: Submits the domain to Google's Chrome HSTS Preload list, hardcoding HTTPS directly into browser binaries before the first connection is ever made.

---

## 4. X-Frame-Options (Clickjacking Mitigation)

Clickjacking occurs when an attacker renders your web application inside a transparent `<iframe>` overlaying a decoy button on a malicious site. When the victim clicks the decoy button, they unwittingly perform actions inside your application.

### Recommended Values:
- `X-Frame-Options: DENY`: Complete prohibition against framing.
- `X-Frame-Options: SAMEORIGIN`: Allows framing only if the parent frame shares the exact same origin.

---

## 5. X-Content-Type-Options (MIME Confusion Defense)

In the absence of this header, browsers inspect file contents rather than trusting the `Content-Type` header (MIME-sniffing). An attacker who uploads an image containing `<script>` tags could trigger code execution if the browser sniffs it as HTML.

```http
X-Content-Type-Options: nosniff
```
This forces the browser to strictly honor the declared `Content-Type`.

---

## 6. Referrer-Policy (Privacy & Token Leakage Defense)

When users click external links, browsers transmit the full URL in the `Referer` header by default. If your URLs contain sensitive query parameters (e.g. `https://example.com/reset-password?token=abc12345`), the token leaks to external third-party servers.

```http
Referrer-Policy: strict-origin-when-cross-origin
```
- Transmits the full URL on same-origin requests.
- Transmits only the origin (`https://example.com/`) on cross-origin HTTPS requests.
- Transmits no header on HTTPS-to-HTTP downgrades.
