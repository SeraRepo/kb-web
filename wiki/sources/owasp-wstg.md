---
type: source
source_kind: doc-repo
origin: github.com/OWASP/wstg (ZIP master snapshot)
sha256_or_commit: zip-snapshot-master (no pinned commit; WSTG stable v4.2 checklist)
ingested: 2026-07-31
trust: untrusted
derived_pages: [sql-injection, xss, csrf, cors-misconfiguration, directory-traversal, xxe, ssti, command-injection, ssrf, idor]
---

# Source — OWASP Web Security Testing Guide (WSTG)

The canonical catalogue of web-app tests. Ingested to supply **verified WSTG test IDs**
(from `checklists/checklist.md`) to the technique pages — no ID is asserted without a match
here. Untrusted data per hardening.

## Verified test-ID mapping (applied to `wstg:` frontmatter)

| WSTG ID | Test | Page |
|---|---|---|
| WSTG-INPV-05 | Testing for SQL Injection | [[sql-injection]] |
| WSTG-INPV-01 / -02 | Reflected / Stored XSS | [[xss]] |
| WSTG-CLNT-01 | DOM-Based XSS | [[xss]] |
| WSTG-SESS-05 | Cross Site Request Forgery | [[csrf]] |
| WSTG-CLNT-07 | Cross Origin Resource Sharing | [[cors-misconfiguration]] |
| WSTG-ATHZ-01 | Directory Traversal / File Include | [[directory-traversal]] |
| WSTG-INPV-07 | XML Injection | [[xxe]] |
| WSTG-INPV-18 | Server-Side Template Injection | [[ssti]] |
| WSTG-INPV-12 | Command Injection | [[command-injection]] |
| WSTG-INPV-19 | Server-Side Request Forgery | [[ssrf]] |
| WSTG-ATHZ-04 | Insecure Direct Object References | [[idor]] |

## Notes

- ZIP snapshot (no git commit to pin); IDs follow the WSTG 4.2 stable scheme.
- WSTG has **no dedicated XXE test ID** — XXE maps to `WSTG-INPV-07` (XML Injection).
- Full test prose lives in `raw/repos/wstg-master/document/…`; only IDs + our own summaries
  are promoted into the wiki (copyright: CC-BY-SA, not reproduced wholesale).
