---
type: source
source_kind: guide
origin: raw/guides/web-200.pdf
sha256_or_commit: 31F64B2E6C1946B67E17D92DCAF9BEDA5C96173A6A7096316DD6C88F00B6FDB3
ingested: 2026-07-31
trust: untrusted
derived_pages: [sql-injection, xss, csrf, cors-misconfiguration, directory-traversal, xxe, ssti, command-injection, ssrf, idor, sql-enumeration, same-origin-policy, samesite-cookies, xml-entities, templating-engines, burp-suite, sqlmap, parameterized-queries, output-encoding, content-security-policy, csrf-tokens, web-app-assessment]
---

# Source — OffSec WEB-200 "Web Attacks with Kali Linux" (OSWA)

Official OffSec course material for the **OSWA** certification (WEB-200, *Web Attacks
with Kali Linux*), © 2025 OffSec Services Limited. This is a **licensed personal copy**
(watermarked to the owner). Treated as **untrusted** input per hardening: payloads are
described/quoted in inert code blocks, never executed; nothing here is fetched or run.

**Copyright:** wiki pages synthesise this material **in our own words** with attribution
back to this slug — no wholesale reproduction of the course prose or its payload listings.

## Scope & coverage (449 pp., 16 modules)

- **Methodology & tooling:** Web application enumeration methodology (recon, service &
  endpoint discovery, wordlists) · Burp Suite (Proxy, Repeater, Comparer, Intruder,
  Decoder) · "Assembling the Pieces" assessment breakdown + challenge machines.
- **Techniques:** Cross-Site Scripting (reflected/stored, server/client) & exploitation
  · Cross-origin attacks (Same-Origin Policy, SameSite, CSRF, CORS) · SQL (per-DBMS
  enumeration) & SQL Injection · Directory Traversal · XML External Entities (XXE) ·
  Server-Side Template Injection (Twig, Freemarker, Pug, Jinja, Handlebars) · Command
  Injection · Server-Side Request Forgery (SSRF) · Insecure Direct Object References (IDOR).
- **Case studies (real apps):** Shopizer, Apache OFBiz, Piwigo, Home Assistant, Halo,
  Craft CMS, OpenNetAdmin, Group Office, OpenEMR — used as the *worked examples* on the
  corresponding technique pages.

## Character of the material

Hands-on, lab-driven, black/grey-box web exploitation aimed at the OSWA exam (no
chatbots allowed — hence this wiki must stand alone offline). Strong on **methodology**
(enumerate → discover → exploit → confirm impact) and on turning a real app finding into
a reproducible exploitation chain.

## Ingestion status — all content modules done (2026-07-31)

- [x] Mod 3 + 16 — [[web-app-assessment]] (methodology hub)
- [x] Mod 4 — [[burp-suite]]
- [x] Mod 5–6 — [[xss]]
- [x] Mod 7 — [[csrf]], [[cors-misconfiguration]] (+ [[same-origin-policy]], [[samesite-cookies]])
- [x] Mod 8–9 — [[sql-injection]] (+ [[sql-enumeration]], [[sqlmap]], [[parameterized-queries]])
- [x] Mod 10 — [[directory-traversal]]
- [x] Mod 11 — [[xxe]] (+ [[xml-entities]])
- [x] Mod 12 — [[ssti]] (+ [[templating-engines]])
- [x] Mod 13 — [[command-injection]]
- [x] Mod 14 — [[ssrf]]
- [x] Mod 15 — [[idor]]
- Modules 1–2 (copyright, course intro) intentionally not paged — no reusable technique content.

**Follow-ups (for lint):** WSTG + ASVS IDs now populated (see [[owasp-wstg]], [[owasp-asvs]]);
`targets/` pages (SPA/API, GraphQL, SSO/OAuth, WebSocket) not yet created.
