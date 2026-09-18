---
type: technique
title: NoSQL injection
lang: en
status: draft
wstg: ["WSTG-INPV-05"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: []
cwe: ["CWE-943"]
attack: []
cvss: ""
sources: [colleague-web-wiki]
updated: 2026-09-17
---

# NoSQL injection

**TL;DR** — Injecting **query operators** (not SQL) into a NoSQL backend (MongoDB, …) — typically
by switching a form login to a JSON body and passing `{"$ne":…}`/`{"$gt":…}`/`{"$regex":…}` —
bypasses authentication or blind-extracts data. Confirmed twice in the 0xdf gap-analysis (HTB
*Overgraph*, *NodeBlog*); currently only reachable in the KB via [[graphql-api|GraphQL]] resolver
injection.

> **Stub (draft)** — Framework: **A03:2021 – Injection**, `CWE-943`, WSTG under
> `WSTG-INPV-05` (SQLi test, NoSQL variant). Sibling of [[sql-injection]].

## Scope to cover

- **Auth bypass** — flip the login to `Content-Type: application/json` and inject an operator:
  ```json
  {"username":"admin","password":{"$ne":"x"}}
  ```
  In-URL form: `user[$ne]=x&pass[$ne]=x`.
- **Operator injection** — `$ne`, `$gt`, `$gte`, `$in`, `$regex`, `$exists`.
- **Blind extraction** — `$regex` char-by-char (`{"password":{"$regex":"^a.*"}}`), boolean/timed.
- **JS execution** — Mongo `$where`/`mapReduce` with attacker JS (`$where: "sleep(5000)"`).
- **GraphQL/API resolvers** — the same operators through a JSON-typed arg (see [[graphql-api]]).
- Tooling: [[burp-suite|Burp]] (tamper JSON), `nosqlmap`.

## Detection

Submit `'`/`"`/`{"$gt":""}`; a login that succeeds with `{"$ne":null}` or errors differently on
an operator is NoSQL-injectable. Watch the `Content-Type` the endpoint accepts.

## Remediation

Reject/cast user input to the expected scalar type (not objects); disable `$where`/JS; use an
ODM with strict schemas; parameterise; validate `Content-Type`. (Cross-check
[[colleague-web-wiki|injection-prevention]].)

## See also

[[sql-injection]] · [[graphql-api]] · [[authentication-attacks]] · [[oswa-exam]]

*Source: [[colleague-web-wiki]] (injection); 0xdf HTB gap-analysis (Overgraph `$ne` OTP bypass, NodeBlog `$ne` login bypass).*
