# Proxy Networks, IP Reputation & Egress Routing Architecture

This reference guide details proxy classification, IP reputation dynamics, egress IP pooling, and sticky session management required to sustain high-volume scraping through Cloudflare.

---

## 1. Proxy Categories & Cloudflare Threat Scoring

Cloudflare assigns a real-time **Threat Score (0 to 100)** to every incoming IP address based on global sensor telemetry, ASN classification, and connection frequency.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Proxy Category Comparison                       │
├───────────────────┬──────────────┬───────────┬───────────┬─────────────┤
│ Category          │ ASN Class    │ Threat    │ CF Pass   │ Cost / GB   │
│                   │              │ Score     │ Rate      │             │
├───────────────────┼──────────────┼───────────┼───────────┼─────────────┤
│ **Datacenter**    │ Hosting ASN  │ High      │ 15%–35%   │ $0.001–$0.01│
│ **CF Worker**     │ Cloudflare   │ Very Low  │ 75%–90%   │ Free/$0.0001│
│ **Static ISP**    │ Consumer ISP │ Very Low  │ 92%–97%   │ $1.50–$3.00 │
│ **Residential**   │ P2P Consumer │ Low       │ 95%–99%   │ $2.00–$6.00 │
│ **Mobile (4G/5G)**│ Mobile CGNAT │ Zero      │ 99.5%     │ $8.00–$15.00│
└───────────────────┴──────────────┴───────────┴───────────┴─────────────┘
```

### Why Mobile (4G/5G) Proxies Have Near-100% Pass Rates:
Mobile cellular networks use Carrier-Grade NAT (CGNAT). Thousands of real smartphone users share a single public IPv4 address simultaneously. Cloudflare cannot block or heavily challenge a CGNAT IP without blocking thousands of legitimate human mobile subscribers.

---

## 2. Sticky Sessions vs Rotating Pools with `cf_clearance`

A critical architectural pitfall is using a "rotating-on-every-request" proxy with Cloudflare cookies:

```
[WRONG: Rotating Proxy on Every Request]
Request 1 (Solve Challenge) ──► IP: 198.51.100.10 ──► Receives cf_clearance
Request 2 (Fetch Data API)  ──► IP: 198.51.100.42 (IP CHANGED!) ──► HTTP 403 FORBIDDEN!
(Cloudflare drops clearance because egress IP changed)

[CORRECT: Sticky Session Architecture]
Request 1 (Solve Challenge) ──► IP: 198.51.100.10 ──► Receives cf_clearance
Request 2 (Fetch Data API)  ──► IP: 198.51.100.10 (Sticky for 25 mins) ──► HTTP 200 OK!
Request 3 (Fetch Media)     ──► IP: 198.51.100.10 (Sticky for 25 mins) ──► HTTP 200 OK!
```

### Prescribed Rule:
Always maintain **Sticky IP Sessions** (minimum 20–30 minutes) per domain to match the lifetime of the issued `cf_clearance` cookie.

---

## 3. Serverless Edge Rotation (AWS Lambda / Cloudflare Workers)

For low-cost, high-volume bypass without paying expensive residential proxy bandwidth fees:

### Architecture:
```
[Client App] ──► [Pool of 50 Cloudflare Workers / AWS Lambda Handlers] ──► [Target Domain]
```
- Each AWS Lambda execution is assigned an ephemeral IP from Amazon's large IP ranges.
- Cloudflare Workers originate from within Cloudflare's own ASN (`AS13335`), which many target domains whitelist or trust by default.
