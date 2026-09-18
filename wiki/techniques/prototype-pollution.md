---
type: technique
title: Prototype pollution
lang: en
status: draft
wstg: ["WSTG-INPV-22"]
owasp_top10: ["A08:2021"]
owasp_api: []
asvs: []
cwe: ["CWE-1321"]
attack: []
cvss: ""
sources: [colleague-web-wiki]
updated: 2026-09-17
---

# Prototype pollution

**TL;DR** — In JavaScript, injecting `__proto__`/`constructor.prototype` keys into an object a
recursive merge/clone touches pollutes **every** object's prototype — flipping logic flags,
escalating privilege, or reaching RCE (server-side) or DOM XSS (client-side). Confirmed twice in
the 0xdf gap-analysis (HTB *Unobtainium*, *Pollution*).

> **Stub (draft)** — Framework: **A08:2021**, `CWE-1321`, WSTG `WSTG-INPV-22`, ASVS V5.

## Scope to cover

- **Sinks:** unsafe recursive merge/clone — `lodash` `_.merge`/`_.defaultsDeep`/`_.set`,
  `Object.assign` on parsed JSON, query-string/`Object`-deep parsers, config loaders.
- **Vector:** a JSON body / query with `__proto__` (or `constructor.prototype`):
  ```json
  {"__proto__":{"isAdmin":true,"canUpload":true}}
  ```
- **Server-side → RCE:** pollute options later read by `child_process` — `NODE_OPTIONS`,
  `argv0`, `shell`, `env` — then trigger a spawn:
  ```json
  {"__proto__":{"argv0":"node","shell":"/bin/sh","NODE_OPTIONS":"--require /proc/self/environ"}}
  ```
- **Logic bypass:** flip an authz/upload flag globally (HTB *Unobtainium* `canUpload`).
- **Client-side (DOM):** polluted prototype reaches an HTML/`innerHTML` gadget → DOM [[xss]].

## Detection

Send `?__proto__[test]=polluted` / a JSON `__proto__` and check whether an unrelated object
gains `test`; look for `_.merge`/`Object.assign` on user JSON; server crashes/behaviour change.

## Remediation

`Object.create(null)` / `Map` for user-keyed data; freeze `Object.prototype`; reject
`__proto__`/`constructor`/`prototype` keys; use `Map`; patch vulnerable lodash/merge libs; schema
validation. (Cross-check [[colleague-web-wiki|prototype-pollution-prevention]].)

## See also

[[xss]] · [[command-injection]] · [[graphql-api]] · [[oswa-exam]]

*Source: [[colleague-web-wiki]] (WSTG-INPV-22); 0xdf HTB gap-analysis (Unobtainium, Pollution — lodash `_.merge` → flag flip / RCE).*
