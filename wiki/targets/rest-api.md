---
type: target
title: REST / JSON API attack surface
lang: en
status: active
wstg: ["WSTG-APIT-01"]
owasp_top10: []
owasp_api: ["API1:2023", "API2:2023", "API3:2023", "API5:2023", "API7:2023", "API8:2023"]
asvs: ["V4.1.3", "V4.1.4"]
cwe: []
cvss: ""
sources: [hacktricks, colleague-web-wiki]
updated: 2026-09-17
---

# REST / JSON API attack surface

A REST/JSON API exposes structured, guessable endpoints across HTTP verbs — which makes
**authorization** bugs both common and easy to enumerate. This page maps the surface to the
[OWASP API Security Top 10 (2023)]; the ordered run-book is [[api-testing]], the GraphQL sibling
is [[graphql-api]].

## Recon — do this first

- **Specs/docs:** `openapi.json`, `swagger.json`, `/swagger-ui`, `/api-docs`, `/v2/api-docs`,
  `?wsdl` (SOAP). Import into Postman/Burp; audit the spec (weak auth, verbs).
- **Route discovery:** **Kiterunner** (API-route wordlists) + [[ffuf]]; watch for `/v1 /v2 /v3
  /beta` — **old versions are often unpatched** ([[idor|BOLA]] fixed in v2 but not v1).
- **Auth model:** cookie vs `Authorization: Bearer` ([[jwt-attacks|JWT]]) vs API key. Grab two
  accounts (low + normal) — access-control bugs need them.

## The Top 10 as a test list

| API# | Class | Concrete check | KB |
|---|---|---|---|
| **API1** | BOLA (object authz) | swap every object id (path/body/query) across accounts: `GET /users/1001/card` → `1002` | [[idor]] |
| **API2** | Broken authentication | missing/`none`/weak-secret/expired JWT accepted; token of A used for B; reset/OTP brute (no rate limit) | [[jwt-attacks]] · [[authentication-attacks]] |
| **API3** | BOPLA / mass assignment | add fields the client shouldn't set (below); or responses over-expose (`password_hash`, other users' PII) | [[idor]] |
| **API5** | BFLA (function authz) | call admin/other-group endpoints as low-priv; verb-swap to an admin action | *below* |
| **API7** | SSRF | URL/host/file fields (webhook, `image_url`, `callback`, PDF/render) → internal / cloud metadata | [[ssrf]] |
| **API8** | Misconfiguration | reflected-origin CORS + creds; verbose errors; extra verbs (`PUT`/`TRACE`); Content-Type swap → XXE | [[cors-misconfiguration]] · [[xxe]] |
| **API4** | Resource consumption | oversized `limit`/page, huge bodies, no rate limit on costly (SMS/OTP) endpoints | — |
| **API6** | Business-flow abuse | automate a human-paced flow (bulk buy, coupon/referral abuse, mass signup) | — |
| **API9** | Improper inventory | shadow/zombie endpoints, staging hosts, deprecated live routes; pivot `/v2`→`/v1` | — |
| **API10** | Unsafe consumption | the API trusts an upstream/3rd-party blindly; inject via ingested data, follow redirects | — |

### Mass assignment (BOPLA) — the highest-value REST trick

Send extra JSON properties the server binds without an allow-list:

```json
{"username":"eve","email":"eve@x.tld","role":"admin","isAdmin":true,"verified":true}
```
Diff what the UI sends vs. what the endpoint accepts. See [[idor]] (write-side of broken access
control).

### BFLA (function-level) — reach admin functions

As a low-priv (or anonymous) user, call an administrative endpoint or switch the verb; never infer
"admin-only" from the URL:

```http
POST /api/admin/v1/users/export_all          # guessed from a non-admin route; no function-level check
```
Signal: a non-privileged token getting `200`/an effect where `401/403` is expected. Root cause
`CWE-285`. Tooling: [[burp-suite|Burp]] Autorize (role-diff across accounts).

## Core request-tampering toolkit (applies across the list)

```text
Method swap:   GET→POST/PUT/PATCH/DELETE ; X-HTTP-Method-Override: PUT (when verbs are filtered)
ID enum:       numeric ±1, swap UUIDs harvested elsewhere, arrays of ids, wildcard * / %
Extra params:  HPP (?id=1&id=2), duplicate JSON keys, inject role/isAdmin
Type juggling: "1" vs 1, arrays vs scalars, null, nested object where a string is expected
Version pivot: /v1 ↔ /v2 ↔ /v3   (older = weaker)
Content-Type:  application/json ↔ application/xml (→ XXE) ↔ x-www-form-urlencoded (alternate parser)
```

## Gotchas

- **API keys leak** in source, public repos, Docker images, `.env`, logs — hunt with trufflehog /
  gitleaks; validate only against the vendor's own docs endpoint, never third-party services.
- **SOAP** (`?wsdl`) → XXE (try CDATA when DTD is blocked), MTOM/XOP file read.
- Rate limits are usually per-endpoint — **batching** (or [[graphql-api|GraphQL aliasing]]) beats them.

## Quick checklist

- [ ] Recon: spec (`openapi.json`), route brute (Kiterunner), version pivot, two accounts.
- [ ] BOLA: swap object ids everywhere, all verbs. BFLA: call admin funcs as low-priv / verb-swap.
- [ ] Mass-assign hidden fields (`role`/`isAdmin`); check responses for over-exposed data.
- [ ] Auth: JWT flaws ([[jwt-attacks]]), reset/OTP brute; SSRF on URL fields; CORS + creds.
- [ ] Confirm cross-tenant read/write, privilege escalation, or a control bypass.

## See also

[[api-testing]] · [[graphql-api]] · [[idor]] · [[jwt-attacks]] · [[ssrf]] · [[authentication-attacks]]

*Sources: [[hacktricks]] (web-API pentesting techniques, key-leak tooling); [[colleague-web-wiki]] (OWASP API Top 10 surface, BFLA/CWE-285).*

[OWASP API Security Top 10 (2023)]: https://owasp.org/API-Security/
