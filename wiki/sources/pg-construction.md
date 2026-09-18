---
type: source
source_kind: writeup
origin: raw/web/Walkthrough Construction.md (portal.offsec.com/machine/construction-182546)
sha256_or_commit: 3BC3450477E355BC0D267C2CF91396EF14096D9FF8C5D310425C3A1E04610572
ingested: 2026-09-17
trust: untrusted
derived_pages: [xss]
---

# Source — OffSec PG "Construction" walkthrough

A walkthrough clipping for the OffSec Proving Grounds machine **Construction** (Hard),
supplied by the user in `raw/web/`. OffSec-copyrighted content — summarised **in our own
words**, payloads quoted in inert blocks; nothing here is fetched or run, and the hosts named
(`192.168.x`, the target) are **never contacted** per hardening.

## What it teaches (OSWA-relevant)

A textbook **blind stored [[xss]] → RCE pivot**, the highest-value XSS pattern for exams:

1. A public booking form (`name`/`message`) is stored unsanitised and rendered later in an
   **admin dashboard** the attacker can't see → blind XSS. Confirmed by an external
   `<script src>` beacon that calls back to the attacker's host.
2. First-stage JS exfiltrates the admin page's DOM (base64) → reveals a hidden dashboard URL.
3. The dashboard has a **localhost-only** "run command" endpoint. Because the injected JS runs
   in the admin's browser *on localhost*, it calls that endpoint (fetch POST) to run a command
   and stage a reverse shell → root.

Lessons filed into [[xss]] (new "Blind XSS & weaponising an admin viewer" section): blind-XSS
callback discovery, DOM exfiltration, and using in-origin execution to defeat a network/origin
restriction — the same reason XSS defeats [[csrf]] tokens.

*Integrated into: [[xss]]. Target class: classic server-rendered app (Flask/Gunicorn).*
