---
type: source
source_kind: writeup
origin: raw/web/Walkthrough Fullmoon.md (portal.offsec.com/machine/fullmoon-191957)
sha256_or_commit: 598F12122B070A8E110410E2CA5612B260D84E53E6804DE070546A4179A26E12
ingested: 2026-09-17
trust: untrusted
derived_pages: [ssrf, idor, ssti]
---

# Source — OffSec PG "Fullmoon" walkthrough

A walkthrough clipping for the OffSec Proving Grounds machine **Fullmoon** (Medium, Node.js
/ Express), supplied by the user in `raw/web/`. OffSec-copyrighted — summarised **in our own
words**, payloads in inert blocks; hosts named are **never contacted**.

## What it teaches (OSWA-relevant)

Two chains, both good exam material:

- **[[ssrf]] (0.0.0.0 bypass) → [[idor]]:** a "website analysis" feature screenshots a
  user-supplied URL via headless Chromium. The denylist blocks only the literal strings
  `localhost` / `127.0.0.1`, so **`http://0.0.0.0/`** reaches loopback. Screenshots save to a
  predictable path `fullmoon-demo-screenshots-<N>.png` (a static-file IDOR, enumerated with
  [[ffuf]] over `seq 1 50`). Sensitive screenshots return `403`, so the SSRF is pointed at
  those internal screenshot URLs — screenshot the screenshots — leaking the **admin password**
  → login → `local.txt`.
- **EJS [[ssti]] with a keyword filter:** report **Templates** render **EJS**
  (`49 -> <%= 7*7 %>` → `49 -> 49`). An exported `server.js` backup shows a middleware that
  strips `process`/`require`/`exec` with a single `String.replace(/word/g,'')`. Bypassed by
  **nesting the keyword in itself** (`procprocessess` → `process`) → `child_process` reverse
  shell → `proof.txt`.

Lessons filed into [[ssrf]] (0.0.0.0 loopback bypass + SSRF-over-IDOR worked example), [[idor]]
(predictable-filename IDOR + 403-isn't-access-control), and [[ssti]] (EJS engine + the
regex-replace-once keyword-filter bypass).

*Integrated into: [[ssrf]], [[idor]], [[ssti]]. Target class: SPA/API-ish Node app.*
