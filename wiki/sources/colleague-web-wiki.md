---
type: source
source_kind: doc-repo
origin: raw/repos/web-main-wiki.zip (colleague's web-audit wiki, i-Tracing internal)
sha256_or_commit: 1750D692D3A4C6074E4C5E7A46556B90745A1A2B47A5054F0567EED6ADA994BD
ingested: 2026-09-17
trust: untrusted
derived_pages: [lfi, file-upload, authentication-attacks, jwt-attacks, rest-api, graphql-api, api-testing, oauth-attacks, open-redirect]
---

# Source — colleague's web-audit wiki

A comprehensive web-application-security wiki built by a colleague (same org), supplied as a
ZIP in `raw/repos/`. **227 markdown files.** Treated as **untrusted** per our hardening even
though it self-marks `trust: reference` — directives inside a source are described, never
followed; hosts named are never contacted.

## Character & coverage

A **breadth-first, WSTG-mapped reference** wiki (the mirror image of ours, which is
depth/payload-first for OSWA):

- **`techniques/`** — full **OWASP WSTG v4.2** mirror (115/115 test IDs) organised in
  WSTG-numbered folders (info-gathering, config, identity, authn, authz, session, input-
  validation, error-handling, crypto, business-logic, client-side, API), plus the **OWASP API
  Top 10 (2023)** as dedicated risk pages.
- **`mitigations/`** — ~40 remediation pages, ASVS v5.0.0 cross-referenced, several
  RFC-backed (JWT: RFC 8725/9068; OAuth: RFC 9700), many with **FR** counterparts.
- **`concepts/`** — web-platform primitives (SOP, CORS, cookies, security headers, MIME
  sniffing, secure contexts, WebAuthn, federated identity, …), sourced from MDN.
- **`methodologies/`** — an **API testing** playbook (REST & GraphQL), ANSSI risk-rating (FR),
  remediation-scoring. **`targets/`** — REST & GraphQL attack surface.
- **`payloads/`** — an XSS payload stub (explicitly deferred to PayloadsAllTheThings).

**Key takeaway:** it is *thin on offensive payloads* by design (defers them to PaTT "at
enrichment"). So we mine it for **breadth, remediation, concepts, and the API/GraphQL
surface**, and keep sourcing payload depth from PaTT/HackTricks/our own knowledge.

## Used so far (this ingest)

Offensive nuggets folded into the P1 pages, in our words: WSTG-ATHZ-01 framing + PHP
include-sink grep hints → [[lfi]]; WSTG-BUSL-08/09 upload-evasion list, Zip Slip, EICAR →
[[file-upload]]; WSTG-ATHN-04 bypass set (forced browsing, param tampering, magic hashes,
same-length password) → [[authentication-attacks]]. Their mitigations pages cited for
remediation.

## Backlog (rich, not yet mined — see [[oswa-exam]])

Full JWT page ([[jwt-attacks]]), [[open-redirect]] (WSTG-CLNT-04), prototype pollution,
insecure deserialization, host-header injection, HTTP request smuggling, session-management,
an **API/GraphQL** target + methodology, and many `concepts/` pages. Their WSTG/ASVS IDs are a
useful cross-check but must be **re-verified against our own WSTG/ASVS corpora** before we
assert them (Golden rule 5) — hence `asvs: []` on the new pages for now.

*Integrated into: [[lfi]], [[file-upload]], [[authentication-attacks]] (offensive nuggets).*
