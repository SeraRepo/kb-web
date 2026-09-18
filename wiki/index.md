# Index — Web Application Security Audit KB

Content catalog by ontology category. Each entry: page link · one-line summary · key
framework IDs. Doubles as an offline study map / coverage checklist. Refreshed on every
ingest. `(draft)` = stub awaiting its module.

## Techniques

When the Dataview plugin is enabled, this table auto-populates from frontmatter:

```dataview
TABLE wstg AS "WSTG", owasp_top10 AS "OWASP", cwe AS "CWE", asvs AS "ASVS", status FROM "wiki/techniques" SORT title ASC
```

- [[sql-injection]] — change a query's structure via unsanitised input; UNION/error/blind, files, RCE · A03:2021 · CWE-89
- [[xss]] — reflected/stored/DOM script execution in the victim's origin · A03:2021 · CWE-79
- [[csrf]] — forge state-changing requests using the victim's ambient session · A01:2021 · CWE-352
- [[cors-misconfiguration]] — read cross-origin data via reflected origin / bad allowlist · A05:2021 · CWE-942
- [[directory-traversal]] — escape a base dir with `../` to read/write arbitrary files · A01:2021 · CWE-22
- [[xxe]] — abuse XML external entities for file read / SSRF / OOB exfil · A05:2021 · CWE-611
- [[ssti]] — user input in template source → RCE (Twig/Freemarker/Pug/Jinja) · A03:2021 · CWE-1336
- [[command-injection]] — input reaches an OS command → shells & web shells (RCE) · A03:2021 · CWE-78
- [[ssrf]] — coerce the server into attacker-chosen requests; internal/metadata/file · A10:2021 · CWE-918
- [[idor]] — access others' objects via an unchecked reference · A01:2021 · CWE-639
- [[lfi]] — include/execute a path param → RCE (php wrappers, filter chains, log/session poisoning, RFI) · A03:2021 · CWE-98
- [[file-upload]] — type/name/content/magic-byte bypass → web shell → RCE · A03:2021 · CWE-434
- [[authentication-attacks]] — default/weak creds, brute (hydra/ffuf), enum, bypass, reset & MFA flaws · A07:2021 · CWE-287
- [[jwt-attacks]] — forge tokens: `alg:none`, weak-secret crack, HS/RS confusion, `kid`/`jku`/`jwk` · A07:2021 · API2:2023 · CWE-347
- [[oauth-attacks]] — SSO/OAuth account takeover: `redirect_uri` theft, `state` CSRF, PKCE downgrade, OIDC token confusion · A07:2021 · WSTG-ATHZ-05
- [[open-redirect]] — unvalidated redirect target → phishing; chains into OAuth token theft / SSRF; `javascript:` → XSS · A01:2021 · CWE-601
- [[reverse-shells]] — post-exploitation: reverse/bind shell one-liners (Linux/Windows) + dumb-shell → full-PTY upgrade · ATT&CK T1059
- [[deserialization]] — untrusted serialized data → gadget-chain RCE (PHP/phpggc, Python pickle, Node, Java/ysoserial, .NET ViewState) · A08:2021 · CWE-502
- [[prototype-pollution]] — *(draft)* JS `__proto__` merge → logic bypass / RCE / DOM XSS · A08:2021 · CWE-1321
- [[nosql-injection]] — *(draft)* operator injection (`$ne`/`$regex`/`$where`) → auth bypass / blind extraction · A03:2021 · CWE-943
- [[known-vulnerable-components]] — fingerprint product+version → public CVE → adapt PoC; incl. `.git`/source disclosure · A06:2021 · CWE-1104

## Methodologies

- [[oswa-exam]] — **OSWA exam run-book + coverage matrix + build backlog** (start here for exam prep)
- [[oswa-box-playbook]] — **step-by-step box roadmap** (recon → enumerate → per-input triage → foothold → flags) + a "when stuck" checklist
- [[wstg-checklist]] — master WSTG v4.2 test-plan (all 12 areas) + coverage tracker
- [[api-testing]] — API assessment run-book (REST & GraphQL) mapped to the OWASP API Top 10
- [[web-app-assessment]] — baseline run-book for a classic server-rendered app (hub → all techniques)

## Vulns

_(none yet — finding-pattern pages will land here)_

## Mitigations

- [[parameterized-queries]] — bind data, allowlist identifiers (vs [[sql-injection]])
- [[output-encoding]] — context-aware encoding (vs [[xss]])
- [[content-security-policy]] — CSP defence-in-depth (vs [[xss]])
- [[csrf-tokens]] — synchronizer / double-submit tokens (vs [[csrf]])

## Tools

- [[burp-suite]] — intercepting proxy & platform (Repeater/Intruder/Decoder/Collaborator)
- [[sqlmap]] — automated SQL-injection detection & exploitation
- [[nmap]] — port/service discovery (enumeration entry point)
- [[ffuf]] — fast web fuzzer: content/param/vhost discovery, ID enumeration
- [[gobuster]] — dir/DNS/vhost brute-forcer
- [[wfuzz]] — flexible multi-position web fuzzer
- [[cewl]] — custom wordlist generator (crawl a site)
- [[hydra]] — login brute-forcer (HTTP forms / basic auth)
- [[netcat]] — TCP swiss-army knife; reverse-shell listener
- [[curl]] — scriptable HTTP client; reproduce/automate findings
- [[nikto]] — web server misconfig / known-issue scanner

## Targets

- [[rest-api]] — REST/JSON API attack surface mapped to the OWASP API Top 10 (BOLA, BFLA, mass assignment, SSRF)
- [[graphql-api]] — GraphQL surface: introspection, batching/aliasing, resolver injection, per-resolver authz · WSTG-APIT-99

## Concepts

- [[sql-enumeration]] — per-DBMS metadata queries feeding [[sql-injection]]
- [[same-origin-policy]] — origin isolation; basis for CORS/CSRF
- [[samesite-cookies]] — cross-site cookie sending; Lax/Strict/None (blunts [[csrf]])
- [[xml-entities]] — internal/external/parameter entities (basis for [[xxe]])
- [[templating-engines]] — template vs context; the distinction behind [[ssti]]

## Sources

- [[web-200-oswa]] — OffSec WEB-200 "Web Attacks with Kali Linux" (OSWA), 449 pp. / 16 modules
- [[owasp-wstg]] — OWASP Web Security Testing Guide (verified WSTG test IDs)
- [[owasp-asvs]] — OWASP ASVS 5.0 (verified verification-requirement IDs)
- [[colleague-web-wiki]] — colleague's WSTG/API-mapped web-audit wiki (227 pages; breadth + mitigations, thin on payloads)
- [[pg-construction]] — OffSec PG box: blind stored XSS → admin/localhost weaponisation → RCE
- [[pg-fullmoon]] — OffSec PG box: SSRF (`0.0.0.0`) → IDOR screenshots + EJS SSTI keyword-filter bypass
- [[payloadsallthethings]] — PaTT payload libraries (autonomously fetched per topic → `raw/web/patt-*.md`)
- [[hacktricks]] — HackTricks (secondary payload/methodology source; cloud-SSRF metadata table)
