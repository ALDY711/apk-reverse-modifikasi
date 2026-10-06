# CORS (Cross-Origin Resource Sharing) Hardening Playbook

This reference document outlines the security architecture of Cross-Origin Resource Sharing (CORS), common server-side misconfigurations, and standard hardening patterns.

---

## 1. The Same-Origin Policy (SOP) & CORS Mechanics

The **Same-Origin Policy (SOP)** is a foundational browser security mechanism. It prevents JavaScript running on `https://attacker.com` from reading HTTP responses returned by `https://api.yourbank.com`.

**Cross-Origin Resource Sharing (CORS)** is the W3C standard that allows a server to explicitly relax the SOP for trusted external domains.

```
┌─────────────────┐       GET /api/user (Origin: https://app.trusted.com)      ┌──────────────────┐
│ Browser Client  │───────────────────────────────────────────────────────────►│ API Server       │
│                 │◄───────────────────────────────────────────────────────────│                  │
└─────────────────┘       Access-Control-Allow-Origin: https://app.trusted.com └──────────────────┘
                          Access-Control-Allow-Credentials: true
```

---

## 2. The 3 High-Severity CORS Misconfigurations

### Misconfiguration 1: Arbitrary Origin Reflection with Credentials
```http
// Client Sends:
GET /api/private-data HTTP/1.1
Host: api.victim.com
Origin: https://malicious-site.com
Cookie: session_token=secret123

// Vulnerable Server Responds:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-site.com
Access-Control-Allow-Credentials: true
```
* **Impact:** The victim's browser permits `malicious-site.com` to read the private JSON response, completely compromising authenticated user data.

---

### Misconfiguration 2: Trusting the `null` Origin
Developers frequently allow `null` origin to accommodate local file testing (`file://`) or mobile apps.
```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```
* **Impact:** Any web page can generate a `null` origin request simply by executing a fetch inside a sandboxed iframe:
  ```html
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>fetch('https://api.victim.com/data').then(...)</script>"></iframe>
  ```

---

### Misconfiguration 3: Insecure Regex in Origin Matching
Developers often attempt to whitelist subdomains using unanchored regular expressions:
```php
// VULNERABLE REGEX PATTERN:
if (preg_match('/https:\/\/example\.com/', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
}
```
* **Exploit 1 (Prefix/Suffix bypass):** Matches `https://example.com.attacker.com`
* **Exploit 2 (Hyphen bypass):** Matches `https://example.com-evil.org`

### Secure Regex Pattern:
Always anchor the domain with beginning `^` and ending `$` assertions, and escape literal dots:
```php
if (preg_match('/^https:\/\/(app|portal)\.example\.com$/', $origin)) {
    // Safe
}
```

---

## 3. Production Hardening Patterns

### Laravel (`config/cors.php`):
```php
return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE'],
    // NEVER use ['*'] with supports_credentials => true
    'allowed_origins' => [
        'https://app.yourdomain.com',
        'https://admin.yourdomain.com',
    ],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization', 'X-XSRF-TOKEN'],
    'exposed_headers' => [],
    'max_age' => 86400,
    'supports_credentials' => true,
];
```
