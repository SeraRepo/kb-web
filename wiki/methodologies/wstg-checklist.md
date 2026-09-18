---
type: methodology
title: OWASP WSTG master checklist
lang: en
status: active
sources: [owasp-wstg, web-200-oswa]
updated: 2026-09-17
---

# OWASP WSTG master checklist

A printable, offline **test-plan across all 12 WSTG v4.2 areas** — work it top to bottom on
an assessment or exam, ticking each test. It doubles as this KB's **coverage tracker**: each
row links the technique page that carries the payloads (→ [[page]]) or marks a gap
(*no page yet*). IDs are canonical WSTG v4.2 (verified against [[owasp-wstg]]); the deep
payloads live on the linked pages, not here. Baseline flow: [[web-app-assessment]]; OSWA
overlay: [[oswa-exam]].

> **Exam reminder:** OSWA **allows** sqlmap / Nikto / Burp / Tplmap / msfvenom / ysoserial, but
> **bans** auto-exploitation frameworks (`db_autopwn`), mass scanners (Nessus/OpenVAS/…), and
> AI/LLMs. sqlmap is allowed yet noisy — confirm by hand. Enumerate exhaustively; most blocks are
> a missed endpoint, parameter, or filter bypass. **5 targets · 70/100 · 23h45m + 24h report.**

## INFO — Information Gathering

| ID | Check | KB |
|---|---|---|
| INFO-01 | Search-engine / OSINT leakage (Google dorks, cached secrets) | [[web-app-assessment]] |
| INFO-02 | Fingerprint web server (headers, `Server`, error pages) | [[web-app-assessment]] |
| INFO-03 | Review metafiles (`robots.txt`, `sitemap.xml`, `.well-known`) | [[web-app-assessment]] |
| INFO-04 | Enumerate app on the server (vhosts, other apps) | [[nmap]] · [[ffuf]] |
| INFO-05 | Review page content / comments / JS for secrets | [[web-app-assessment]] |
| INFO-06 | Identify entry points (every param, header, cookie, verb) | [[burp-suite]] |
| INFO-07 | Map execution paths (crawl, sitemap the app) | [[burp-suite]] |
| INFO-08 | Fingerprint framework (cookies, paths, favicons) | [[web-app-assessment]] |
| INFO-09 | Fingerprint the application (product + version) | [[nikto]] · [[known-vulnerable-components]] |
| INFO-10 | Map application architecture (WAF, LB, tiers) | [[web-app-assessment]] |

## CONF — Configuration & Deployment Management

| ID | Check | KB |
|---|---|---|
| CONF-01 | Network/infra config (exposed services) | [[nmap]] |
| CONF-02 | App platform config (debug, sample apps, default files) | [[nikto]] |
| CONF-03 | File-extension handling (`.bak`, `.inc`, source disclosure) | [[ffuf]] |
| CONF-04 | Old/backup/unreferenced files (`.git`, `~`, `.swp`) | [[ffuf]] · [[gobuster]] · [[known-vulnerable-components]] |
| CONF-05 | Admin interfaces (hidden `/admin`, consoles) | [[ffuf]] |
| CONF-06 | HTTP methods (PUT/DELETE/TRACE; verb tampering) | [[curl]] |
| CONF-07 | HSTS present? | *no page yet* |
| CONF-08 | RIA cross-domain policy (`crossdomain.xml`) | *no page yet* |
| CONF-09 | File permissions | *no page yet* |
| CONF-10 | Subdomain takeover (dangling CNAME) | *no page yet* |
| CONF-11 | Cloud storage (open S3/blob buckets) | *no page yet* |

## IDNT — Identity Management

| ID | Check | KB |
|---|---|---|
| IDNT-01 | Role definitions (privilege matrix) | [[idor]] |
| IDNT-02 | Registration process (abuse, over-provisioning) | [[authentication-attacks]] |
| IDNT-03 | Account provisioning | [[authentication-attacks]] |
| IDNT-04 | **Account enumeration** (message/timing diff) | [[authentication-attacks]] |
| IDNT-05 | Weak username policy | [[authentication-attacks]] |

## ATHN — Authentication

| ID | Check | KB |
|---|---|---|
| ATHN-01 | Credentials over an encrypted channel | *no page yet* |
| ATHN-02 | **Default credentials** | [[authentication-attacks]] |
| ATHN-03 | Weak lockout mechanism | [[authentication-attacks]] |
| ATHN-04 | **Bypassing the auth schema** (forced browse, param/response tamper) | [[authentication-attacks]] |
| ATHN-05 | Vulnerable "remember password" | [[authentication-attacks]] |
| ATHN-06 | Browser cache weaknesses | *no page yet* |
| ATHN-07 | Weak auth methods | [[authentication-attacks]] |
| ATHN-08 | Weak security question / answer | [[authentication-attacks]] |
| ATHN-09 | **Weak password change / reset** (host-header, token) | [[authentication-attacks]] |
| ATHN-10 | Weaker auth in an alternative channel | [[authentication-attacks]] |
| — | JWT weaknesses (alg:none, weak secret) | [[jwt-attacks]] |

## ATHZ — Authorization

| ID | Check | KB |
|---|---|---|
| ATHZ-01 | **Directory traversal / file include** (LFI/RFI) | [[directory-traversal]] · [[lfi]] |
| ATHZ-02 | Bypassing the authorization schema | [[authentication-attacks]] · [[idor]] |
| ATHZ-03 | Privilege escalation (horizontal/vertical) | [[idor]] |
| ATHZ-04 | **Insecure Direct Object Reference (IDOR)** | [[idor]] |
| ATHZ-05 | **OAuth / OIDC weaknesses** | [[oauth-attacks]] |

## SESS — Session Management

| ID | Check | KB |
|---|---|---|
| SESS-01 | Session-management schema (predictable IDs) | [[authentication-attacks]] |
| SESS-02 | Cookie attributes (`HttpOnly`/`Secure`/`SameSite`) | [[samesite-cookies]] |
| SESS-03 | Session fixation | [[authentication-attacks]] |
| SESS-04 | Exposed session variables | *no page yet* |
| SESS-05 | **Cross-Site Request Forgery (CSRF)** | [[csrf]] |
| SESS-06 | Logout functionality | *no page yet* |
| SESS-07 | Session timeout | *no page yet* |
| SESS-08 | Session puzzling | *no page yet* |
| SESS-09 | Session hijacking | [[xss]] |
| SESS-10 | **JSON Web Tokens** | [[jwt-attacks]] |

## INPV — Input Validation (the injection core)

| ID | Check | KB |
|---|---|---|
| INPV-01 | **Reflected XSS** | [[xss]] |
| INPV-02 | **Stored XSS** | [[xss]] |
| INPV-03 | HTTP verb tampering | [[authentication-attacks]] |
| INPV-04 | HTTP parameter pollution | *no page yet* |
| INPV-05 | **SQL injection** (+ NoSQL variant) | [[sql-injection]] · [[sql-enumeration]] · [[nosql-injection]] |
| INPV-06 | LDAP injection | *no page yet* |
| INPV-07 | **XML injection / XXE** | [[xxe]] |
| INPV-08 | SSI injection | *no page yet* |
| INPV-09 | XPath injection | *no page yet* |
| INPV-10 | IMAP/SMTP injection | *no page yet* |
| INPV-11 | **Code injection (LFI/RFI)** | [[lfi]] |
| INPV-12 | **OS command injection** | [[command-injection]] |
| INPV-13 | Format-string injection | *no page yet* |
| INPV-14 | Incubated vulnerability | [[file-upload]] |
| INPV-15 | HTTP splitting / smuggling | *no page yet* |
| INPV-16 | HTTP incoming request smuggling | *no page yet* |
| INPV-17 | Host-header injection | *no page yet* |
| INPV-18 | **Server-Side Template Injection (SSTI)** | [[ssti]] |
| INPV-19 | **Server-Side Request Forgery (SSRF)** | [[ssrf]] |
| INPV-20 | Mass assignment | [[idor]] |
| INPV-21 | CSV injection | *no page yet* |
| INPV-22 | **Prototype pollution** | [[prototype-pollution]] *(draft)* |
| INPV-23 | **Insecure deserialization** | [[deserialization]] |

## ERRH — Error Handling

| ID | Check | KB |
|---|---|---|
| ERRH-01 | Improper error handling (info leak) | [[web-app-assessment]] |
| ERRH-02 | Stack traces (framework/version/query leak) | [[sql-injection]] |

## CRYP — Weak Cryptography

| ID | Check | KB |
|---|---|---|
| CRYP-01 | Weak TLS / SSL | *no page yet* |
| CRYP-02 | Padding-oracle | *no page yet* |
| CRYP-03 | Sensitive info over unencrypted channels | *no page yet* |
| CRYP-04 | Weak crypto primitives (weak hashes, ECB) | *no page yet* |

## BUSL — Business Logic

| ID | Check | KB |
|---|---|---|
| BUSL-01 | Business-logic data validation | *no page yet* |
| BUSL-02 | Ability to forge requests | [[idor]] |
| BUSL-03 | Integrity checks (tamper hidden fields) | [[idor]] |
| BUSL-04 | Process timing (race conditions) | *no page yet* |
| BUSL-05 | Function usage limits (no rate limit) | [[authentication-attacks]] |
| BUSL-06 | Circumvention of workflows (skip steps) | *no page yet* |
| BUSL-07 | Defenses against misuse | *no page yet* |
| BUSL-08 | **Upload of unexpected file types** | [[file-upload]] |
| BUSL-09 | **Upload of malicious files** | [[file-upload]] |
| BUSL-10 | Payment functionality | *no page yet* |

## CLNT — Client-side

| ID | Check | KB |
|---|---|---|
| CLNT-01 | **DOM-based XSS** | [[xss]] |
| CLNT-02 | JavaScript execution | [[xss]] |
| CLNT-03 | HTML injection | [[xss]] |
| CLNT-04 | Client-side URL redirect (open redirect) | [[open-redirect]] |
| CLNT-05 | CSS injection | *no page yet* |
| CLNT-06 | Client-side resource manipulation | *no page yet* |
| CLNT-07 | **CORS misconfiguration** | [[cors-misconfiguration]] |
| CLNT-08 | Cross-site flashing | *no page yet* |
| CLNT-09 | Clickjacking | *no page yet* |
| CLNT-10 | WebSockets | *no page yet* |
| CLNT-11 | Web messaging (`postMessage`) | [[cors-misconfiguration]] |
| CLNT-12 | Browser storage (localStorage secrets) | [[xss]] |
| CLNT-13 | Cross-site script inclusion (XSSI) | *no page yet* |
| CLNT-14 | Reverse tabnabbing | *no page yet* |
| CLNT-15 | Client-side template injection (CSTI) | [[ssti]] |

## APIT — API

| ID | Check | KB |
|---|---|---|
| APIT-01 | API reconnaissance (docs, schema, endpoints) | [[api-testing]] · [[rest-api]] |
| APIT-02 | Broken object-level authorization (BOLA) | [[idor]] |
| APIT-03 | Excessive data exposure | [[idor]] |
| APIT-04 | Broken function-level authorization (BFLA) | [[idor]] |
| APIT-99 | GraphQL testing | [[graphql-api]] |

## Coverage gaps (lint feed)

WSTG IDs marked *no page yet* are the coverage backlog. A **0xdf HTB gap-analysis (24 boxes,
2026-09-17, see [[oswa-exam]])** confirmed the priorities: [[deserialization]] (INPV-23, the #1
recurring gap), [[prototype-pollution]] (INPV-22) and [[nosql-injection]] are now **drafted** and
need filling to full standard. Remaining *no page yet*: **SSI injection** (INPV-08, confirmed),
**host-header** (INPV-17), **request smuggling** (INPV-15/16), **padding oracle** (CRYP-02),
**clickjacking** (CLNT-09), and a **media-processor** (FFmpeg/ImageMagick) note — several drafted
defensively in the [[colleague-web-wiki]]. *(JWT, OAuth/OIDC, API and GraphQL are covered.)*

## See also

[[oswa-exam]] · [[web-app-assessment]] · [[owasp-wstg]] · [[index]]

*Sources: [[owasp-wstg]] (WSTG v4.2 test IDs, verified); [[web-200-oswa]] (OSWA exam framing).*
