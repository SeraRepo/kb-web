---
type: methodology
title: API assessment run-book (REST & GraphQL)
lang: en
status: active
owasp_api: ["API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023", "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023"]
sources: [colleague-web-wiki, hacktricks]
updated: 2026-09-17
---

# API assessment run-book (REST & GraphQL)

An ordered, exam-usable run-book for a web **API**, paired with the attack-surface pages
[[rest-api]] and [[graphql-api]] and organised by the [OWASP API Security Top 10 (2023)]. Run top
to bottom; get **two accounts** (low + normal privilege) — most API bugs are authorization, and
they need a second identity to prove. This overlays the baseline [[web-app-assessment]].

## Phase 0 — Recon & inventory *(API9)*

- Pull the spec: `openapi.json` / `swagger.json` / `/api-docs` / `?wsdl`; import to Postman/Burp.
- Brute routes (Kiterunner + [[ffuf]]); map every endpoint, verb, parameter, and **version**
  (`/v1 /v2 /beta` — old versions often skip later authz fixes). Note the auth model.
- GraphQL: locate the endpoint and **introspect** the schema ([[graphql-api]]).

## Phase 1 — Authentication *(API2)*

- Map every auth/reset/OTP flow. Test [[jwt-attacks|JWT]] flaws (`alg:none`, weak secret, key
  confusion, `kid`/`jku`), token-of-A-for-B, expired/revoked tokens still accepted, and
  brute-force / credential stuffing where rate limits are missing ([[authentication-attacks]]).

## Phase 2 — Object-level authorization (BOLA) *(API1)*

- On **every** id-bearing endpoint and verb, swap the id for another account's object
  (increment, swap UUID, bulk/list endpoints). A cross-account read/write is [[idor|BOLA]].

## Phase 3 — Function-level authorization (BFLA) *(API5)*

- As a low-priv/anonymous user, reach admin or other-group functions; verb-swap
  (`GET`→`DELETE`/`POST`) to perform actions you shouldn't. Never infer "admin-only" from the URL.
  ([[rest-api]] BFLA; [[burp-suite|Burp]] Autorize for role-diff.)

## Phase 4 — Property-level authorization *(API3)*

- **Mass assignment:** add hidden writable fields (`"role":"admin"`, `"isAdmin":true`). **Excessive
  exposure:** check responses for fields the client shouldn't see (hashes, other users' PII).

## Phase 5 — Injection & SSRF *(API7, API10)*

- Classic injection through parameters/JSON/GraphQL args ([[sql-injection]],
  [[command-injection]], [[xxe]] via a Content-Type swap). **SSRF** on any URL/host/file field
  → internal services / cloud metadata ([[ssrf]]). Unsafe consumption: can you influence upstream
  data the API trusts?

## Phase 6 — Abuse & limits *(API4, API6)*

- Resource consumption (oversized pages/bodies, no rate limit on costly endpoints); business-flow
  automation (bulk buy, coupon abuse, mass signup). **Batching / GraphQL aliasing** beats
  per-request rate limits.

## Phase 7 — Configuration *(API8)*

- CORS (reflected origin + credentials → cross-origin read, [[cors-misconfiguration]]), security
  headers, extra verbs, verbose errors, TLS. Content-Type switching to reach alternate parsers.

## Phase 8 — Reporting

- Per finding: request/response evidence · impact + **CVSS** · remediation mapped to the control
  ([[colleague-web-wiki|rest-api-security]] / [[colleague-web-wiki|graphql-security]] / ASVS). File
  reusable checks back into [[rest-api]] / [[graphql-api]].

## See also

[[rest-api]] · [[graphql-api]] · [[jwt-attacks]] · [[web-app-assessment]] · [[oswa-exam]]

*Sources: [[colleague-web-wiki]] (OWASP API Top 10 playbook & surface); [[hacktricks]] (web-API techniques).*

[OWASP API Security Top 10 (2023)]: https://owasp.org/API-Security/
