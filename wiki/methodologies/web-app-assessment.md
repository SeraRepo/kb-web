---
type: methodology
title: Web application assessment (baseline)
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Web application assessment — baseline run-book

An ordered, exam-usable run-book for a **classic server-rendered web app**. Follow the
phases; at each input, triage by attack type and jump to the technique page. (API/GraphQL,
SSO/OAuth, and WebSocket targets get their own methodologies per the
one-per-target-class rule — to come.)

## Phase 0 — Scope & setup

- Confirm in-scope hosts, credentials, and rules of engagement.
- Proxy the browser through [[burp-suite|Burp]]; set **Target → Scope**; log everything.

## Phase 1 — Reconnaissance

- Passive info gathering: tech stack, framework, server, versions (headers, cookies, error
  pages, favicons, JS bundles).
- Note the language/DBMS guess early — it drives payload choice ([[ssti]] engine,
  [[sql-injection]] DBMS, [[command-injection]] OS).

## Phase 2 — Enumeration

- Discover services with [[nmap]], then HTTP endpoints: manual walk-through **and**
  automated content discovery ([[ffuf]] / [[gobuster]] / [[wfuzz]] + [[burp-suite|Burp]]
  Intruder) with good **wordlists** — SecLists plus custom lists from the app's own
  vocabulary ([[cewl]]). A quick [[nikto]] sweep surfaces known-issue leads.
- Hunt information disclosure (comments, debug, backups, **`.git` / source disclosure**,
  verbose errors) and **components with known vulnerabilities** — fingerprint → CVE → adapt
  the PoC ([[known-vulnerable-components]]).
- **Deliverable of this phase:** a map of every endpoint, parameter, and input sink.

## Phase 3 — Per-input testing (triage)

For **each** input (query/POST/JSON/header/cookie/path), ask what it feeds and test the
matching class:

| The input looks like… | Test for | Page |
|---|---|---|
| reaches a DB query | SQL injection | [[sql-injection]] |
| reflected/stored in a page | XSS | [[xss]] |
| a state-changing action, cookie-auth | CSRF | [[csrf]] |
| cross-origin data read | CORS misconfig | [[cors-misconfiguration]] |
| a filename/path | directory traversal | [[directory-traversal]] |
| XML parsed server-side | XXE | [[xxe]] |
| rendered by a template | SSTI | [[ssti]] |
| passed to an OS command | command injection | [[command-injection]] |
| a URL the server fetches | SSRF | [[ssrf]] |
| an object reference (id/uid/file) | IDOR / broken access control | [[idor]] |

Common attack goals to keep in mind: authentication bypass, data exfiltration, remote code
execution, web-shell upload.

Credential attacks: brute weak logins with [[hydra]] (wordlists from [[cewl]] / SecLists),
watching for lockout, rate-limiting, and per-request CSRF tokens.

## Phase 4 — Exploitation & impact

- Confirm each finding concretely (the "Confirming impact" section on each technique page).
- Tooling: reproduce and automate with [[curl]]; catch reverse shells with [[netcat]]; automate SQLi extraction with [[sqlmap]].
- Chain where possible: [[xxe]]→[[ssrf]], [[sql-injection]]→RCE, [[ssti]]/[[command-injection]]→shell,
  [[idor]]→mass data exposure. XSS in-origin defeats [[csrf]] tokens.

## Phase 5 — Reporting

Per finding: description · reproduction steps · impact + **CVSS** · remediation (map to the
relevant [[parameterized-queries|mitigation]] / ASVS requirement). File reusable write-ups
back into the wiki.

## OSWA / challenge-machine tips

- Enumerate exhaustively before exploiting — most "stuck" moments are missed endpoints or
  parameters.
- Time-box each host; rotate when blocked; revisit with the tech-stack guess refined.
- Keep notes greppable and screenshots per step (report evidence).

*Source: [[web-200-oswa]] modules 3 (enumeration methodology) & 16 (Assembling the Pieces / challenge machines).*
