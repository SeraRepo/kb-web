---
type: technique
title: Insecure Direct Object Reference (IDOR)
lang: en
status: active
wstg: ["WSTG-ATHZ-04"]
owasp_top10: ["A01:2021"]
owasp_api: []
asvs: ["V8.2.2"]
cwe: ["CWE-639"]
attack: []
cvss: ""
sources: [web-200-oswa, pg-fullmoon]
updated: 2026-09-17
---

# Insecure Direct Object Reference (IDOR)

**TL;DR** — The app exposes a reference to an object (an ID, filename, key) and acts on it
**without checking the current user is allowed that object**. Change the reference to
someone else's and you read or modify their data. IDOR is a broken-access-control failure,
not an injection.

> Framework: **A01:2021 – Broken Access Control**, `CWE-639`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Where it applies

Any request carrying an object reference: `?uid=`, `?id=`, `noteid`, `docid`, `account`,
`invoice`, `file=`, a path segment, or a reference buried in a POST/JSON body. Both
**horizontal** (other users' objects at your privilege level) and **vertical** (objects you
shouldn't reach at all) access.

## Types

- **Static file IDOR** — predictable file paths/names (`/exports/report_1004.pdf`).
- **Database object (ID-based)** — a numeric/sequential primary key (`?uid=57191`); iterate.
- **Complex / obfuscated** — encoded, hashed, or composite references; still IDOR if the
  value is guessable/enumerable or leaks elsewhere and the server skips the ownership check.

## Testing

1. Authenticate (ideally two accounts) and capture a request that returns an object in
   [[burp-suite|Burp]].
2. **Swap the reference** for one belonging to the other account. If you get their data,
   it's IDOR. No second account? **iterate/fuzz** the ID (increment/decrement, Intruder) and
   compare responses.
3. Repeat for every verb — read *and* write (changing another user's object is higher impact).

## Exploitation

Harvest data by iterating the reference; modify objects you shouldn't; escalate if an
admin-owned object is reachable. Automate enumeration and diff responses to find the ones
that leak.

## API context & related patterns

- **BOLA (API IDOR):** object IDs in a REST/GraphQL path or body (`/api/users/1023`) are the
  top API risk — test every object-bearing endpoint with a second account.
- **Mass assignment / BOPLA:** binding extra fields the server shouldn't accept
  (`"role":"admin"`, `"user_id":2`) — the write-side cousin of IDOR.
- **UUIDs are not access control:** unguessable IDs only slow enumeration; the missing
  ownership check is still the bug (and IDs leak via listings, emails, referrers).

Automate enumeration and diff responses with [[ffuf]] (or [[burp-suite|Burp]] Intruder);
reproduce with [[curl]].

## Worked example — OpenEMR

From [[web-200-oswa]] (logged in as low-privileged `lowpriv`). In patient messaging,
clicking **Print Message** with [[burp-suite|Burp]] intercept on reveals a request keyed by a
**`noteid`** parameter. The server returns the note **without verifying it belongs to the
current user**, so decrementing/iterating `noteid` walks through other users' messages —
e.g. a Help Desk staff note exposing sensitive information about incoming patients. (The
module first demonstrates the pattern on a sandbox via `?uid=` iteration.)

## Worked example — Fullmoon (predictable filenames + SSRF chain)

From [[pg-fullmoon]] (OffSec PG box). Generated screenshots are stored at a predictable path
`.../fullmoon-demo-screenshots-<N>.png` — a **static-file IDOR**; iterating `<N>` with [[ffuf]]
enumerates them. The ones holding sensitive data return `403`, but they're reachable by
chaining an [[ssrf]] screenshot feature (screenshot the screenshot) — recovering admin
credentials. Predictable object names + a missing per-object check = IDOR, and a `403` is not
real access control when a second path reaches the same object.

## Confirming impact

Show retrieval (or modification) of an object owned by another user/role via nothing but a
changed reference. Impact scales with data sensitivity and whether writes are possible;
health/PII data (as in OpenEMR) is High–Critical.

## Remediation

- Enforce an **authorization check on every object access**: does the *current* user own /
  may access *this specific* object? (Don't infer access from the reference being known.)
- Prefer **indirect references** scoped to the session (per-user map) over raw global IDs.
- Unpredictable IDs (UUIDs) are defence-in-depth, **not** a substitute for the access check.

## Quick checklist

- [ ] Request carries an object reference (`id`/`uid`/`noteid`/filename/path, in URL/body/JSON)?
- [ ] Two accounts: swap the reference → get the other user's object = IDOR. No 2nd account → iterate/fuzz.
- [ ] Test every verb: read AND write (changing another user's object is higher impact).
- [ ] Predictable filenames / sequential IDs → enumerate ([[ffuf]]); a `403` isn't access control if a 2nd path reaches the object.
- [ ] Confirm access to another user/role's data via nothing but a changed reference.

## See also

[[burp-suite]] · [[web-app-assessment]] · [[csrf]]

*Sources: [[web-200-oswa]] module 15 (OpenEMR); [[pg-fullmoon]] (predictable-filename IDOR chained with SSRF).*
