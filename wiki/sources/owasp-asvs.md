---
type: source
source_kind: doc-repo
origin: github.com/OWASP/ASVS (ZIP master snapshot)
sha256_or_commit: zip-snapshot-master (no pinned commit; ASVS 5.0.0)
ingested: 2026-07-31
trust: untrusted
derived_pages: [sql-injection, xss, csrf, cors-misconfiguration, directory-traversal, xxe, ssti, command-injection, ssrf, idor, parameterized-queries, output-encoding, content-security-policy, csrf-tokens, lfi, file-upload, authentication-attacks, jwt-attacks, oauth-attacks, rest-api, graphql-api, open-redirect, deserialization]
---

# Source — OWASP Application Security Verification Standard (ASVS) 5.0

Verification requirements used to map defensive controls onto techniques/mitigations.
**ASVS 5.0 reorganised the chapters and requirement IDs vs 4.0** — every ID below was
verified against `5.0/en/` (not carried over from 4.0 memory). Untrusted data per hardening.

## Verified requirement mapping (applied to `asvs:` frontmatter)

| ASVS 5.0 | Requirement (summary) | Page(s) |
|---|---|---|
| V1.2.4 | Parameterised DB queries / ORM | [[sql-injection]], [[parameterized-queries]] |
| V1.2.1 / V1.2.3 / V1.1.2 | Context-aware output encoding; JS/JSON; encode as final step | [[xss]], [[output-encoding]] |
| V1.2.5 | OS command injection (parameterised OS calls) | [[command-injection]] |
| V1.3.7 | Template injection — no templates from untrusted input | [[ssti]] |
| V1.3.6 | SSRF — allowlist protocols/domains/paths/ports | [[ssrf]] |
| V1.5.1 | XML parser hardening — disable external entities | [[xxe]] |
| V5.3.2 | File-path handling — path traversal / LFI / RFI / SSRF | [[directory-traversal]], [[lfi]] |
| V5.2.2 / V5.3.1 / V5.3.3 | File upload — content+extension validation, no server-side exec, zip-slip | [[file-upload]] |
| V8.2.2 | Data-specific access control — IDOR / BOLA | [[idor]] |
| V3.3.2 / V3.5.3 | SameSite cookies; non-safe methods & Sec-Fetch validation | [[csrf]], [[csrf-tokens]] |
| V3.4.2 | CORS `Access-Control-Allow-Origin` allowlist | [[cors-misconfiguration]] |
| V3.1.1 | Documented browser security features incl. CSP | [[content-security-policy]] |
| V9.1.1 / 9.1.2 / 9.1.3 / 9.2.3 | Self-contained tokens — verify sig, alg-allowlist (no None), trusted key source (jku/x5u/jwk), audience | [[jwt-attacks]] |
| V10.4.1 / 10.4.6 / 10.2.1 / 10.2.2 / 10.5.1 | OAuth/OIDC — exact redirect_uri, PKCE (reject plain), client CSRF, mix-up (iss), nonce replay | [[oauth-attacks]] |
| V6.3.1 / 6.3.2 / 6.3.8 / 6.4.3 | Auth — anti-brute/stuffing, no default accounts, no user-enum oracle, secure reset | [[authentication-attacks]] |
| V4.1.3 / V4.1.4 | API — intermediary headers not overridable (X-Forwarded-*), only supported HTTP methods | [[rest-api]] |
| V4.3.1 / V4.3.2 | GraphQL — query cost/depth/allowlist (DoS), introspection off in prod | [[graphql-api]] |
| V3.7.2 | Auto-redirect only to an allowlisted host | [[open-redirect]] |
| V1.5.2 | Safe deserialization — type allowlist / no insecure native deserializers | [[deserialization]] |

## Notable 5.0 changes worth knowing

- Injection defences are consolidated under **V1 — Encoding and Sanitization**.
- **CSRF** is framed around **SameSite (V3.3.2)** + non-safe HTTP methods / **Sec-Fetch**
  validation (V3.5.3) + the CORS-preflight mechanism (V3.5.2) — there is *no* dedicated
  anti-CSRF-token requirement (tokens remain a valid complement — see [[csrf-tokens]]).
- ASVS 5.0 explicitly states identifiers and `ORDER BY` column names **cannot be escaped** —
  reinforcing the allowlist point in [[sql-injection]] / [[parameterized-queries]].
- Full requirement text lives in `raw/repos/ASVS-master/5.0/en/` (CC-BY-SA; not reproduced).
