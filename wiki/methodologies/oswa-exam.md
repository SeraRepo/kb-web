---
type: methodology
title: OSWA exam — run-book & coverage matrix
lang: en
status: active
wstg: []
owasp_top10: []
sources: [web-200-oswa]
updated: 2026-09-17
---

# OSWA exam — run-book & coverage matrix

Exam-day playbook for **OSWA** (OffSec Web Assessor, course **WEB-200**), plus the
**coverage matrix** that tracks how ready this KB is and the **build backlog** to close the
gaps. This page is the study spine: it points at every technique/tool page and marks what
still needs densifying. Baseline enumeration flow lives in [[web-app-assessment]]; this page
is the OSWA-specific overlay.

## Exam format & the constraints that shape this KB

- **Format (official OSWA Exam Guide).** **5 independent web targets**, each with a
  `local.txt` (reached through the app) and a `proof.txt` (server filesystem / user home),
  **10 pts per flag → 70/100 to pass**. **23h45m** to exploit + **24h** to submit the report.
  Proctored; Kali over OpenVPN. **No privilege escalation is required** once you have a shell —
  OSWA scores the web vuln + flag. **AI/LLMs are strictly prohibited**, so this wiki must stand
  alone offline (the point of the *Page content standards*).
- **Tooling — allowed vs banned (official guide).** **Allowed:** Nmap+NSE, Nikto, Burp
  (Community/Pro), DirBuster / [[ffuf]] / [[gobuster]], **[[sqlmap]], Tplmap**, and payload
  generators (`msfvenom`, `ysoserial`). **Banned:** spoofing, commercial/enterprise tools
  (Metasploit Pro, Burp Enterprise), **auto-exploitation frameworks** (`db_autopwn`,
  `browser_autopwn`), **mass vulnerability scanners** (Nessus, OpenVAS, NeXpose, Canvas, Core
  Impact, SAINT), and **AI chatbots/LLMs**. So **sqlmap is *allowed*** (unlike OSCP) — but it's
  noisy, not required, and often fails on exam targets, so **confirm the injection by hand
  first** and use sqlmap only to grind extraction. Prefer the manual path for every class.
- **Enumeration wins boxes.** Most "stuck" moments are a missed endpoint, parameter,
  vhost, or a filter you haven't bypassed yet — not a missing exploit.
- **Time-box & rotate.** Don't tunnel on one target; note state, move, return with a
  refined tech-stack guess.
- **OneDrive/Defender note.** This vault is cloud-synced, so live web shells / reverse-shell
  one-liners are kept **defanged** on the pages (see [[command-injection]]); reconstruct
  the working payload at test time.

## OSWA web-target attack flow

An ordered pass for one web box. Each step links to the page that carries the payloads. For the
full **check-as-you-go version with commands and a per-input triage table**, use [[oswa-box-playbook]].

1. **Recon / fingerprint.** Server, framework, language, DBMS guess from headers, cookies,
   error pages, JS bundles. The stack guess drives every payload choice ([[ssti]] engine,
   [[sql-injection]] DBMS, [[command-injection]] OS). See [[web-app-assessment]] Phase 1.
2. **Content & parameter discovery.** [[nmap]] → HTTP; then [[ffuf]] / [[gobuster]] /
   [[wfuzz]] + [[burp-suite|Burp]] Intruder against **SecLists** and a site-specific list
   from [[cewl]]. Find hidden endpoints, params, vhosts, backups, `.git`, verbose errors.
   *Deliverable: a map of every endpoint + input sink.*
3. **Per-input triage.** For each input, test the matching class — the triage table in
   [[web-app-assessment]] Phase 3. OSWA-relevant classes: [[sql-injection]], [[xss]],
   [[directory-traversal]] / [[lfi]], [[file-upload]], [[command-injection]], [[ssti]],
   [[xxe]], [[ssrf]], [[idor]], [[cors-misconfiguration]], [[csrf]],
   [[authentication-attacks]], [[jwt-attacks]], [[open-redirect]].
4. **Exploit manually.** Fingerprint the context → pick the escape → expand payloads under
   filters (each technique page carries the bypass library). Confirm with a benign proof
   (`id`, `document.domain`, DB `version()`).
5. **Foothold.** Turn code execution into a shell; upgrade to a PTY — one-liners and the PTY
   upgrade on [[reverse-shells]]. Catch with [[netcat]] (or socat/pwncat for a stable PTY).
6. **Loot the flag / prove impact.** Read the required proof file / demonstrate the
   concrete impact the report needs.
7. **Evidence as you go.** Greppable notes + a screenshot per step; you reuse them verbatim
   in the report ([[web-app-assessment]] Phase 5).

## Coverage matrix (WEB-200 topics → KB → gap)

Density: **strong** (exam-ready) · **good** (solid, minor adds) · **thin** (needs work) ·
**stub** (draft, to write). Priority: **P1** close first · **P2** next · **P3** nice-to-have.

| WEB-200 topic | KB page | Density | Gap to close for OSWA | Pri |
|---|---|---|---|---|
| Assessment methodology | [[web-app-assessment]] | good | add a printable content-discovery + wordlist checklist | P2 |
| Burp Suite | [[burp-suite]] | good | per-technique recipes (Intruder attack types, Collaborator for blind/OOB) | P2 |
| XSS (reflected/stored/DOM) | [[xss]] | good | bigger filter-bypass / polyglot / CSP-bypass payload library | P1 |
| CSRF | [[csrf]] | good | — | P3 |
| CORS | [[cors-misconfiguration]] | good | — | P3 |
| SQL enumeration (per-DBMS) | [[sql-enumeration]] | good | add **SQLite**; WAF-bypass variants | P2 |
| SQL injection | [[sql-injection]] | strong | reframe **manual-first** (de-emphasise sqlmap); expand auth-bypass + WAF library | P1 |
| Directory traversal | [[directory-traversal]] | good | full encoding-bypass library | P2 |
| **LFI / RFI** | [[lfi]] | good | written 2026-09-17; PaTT payload-depth pass next | P2 |
| **File upload** | [[file-upload]] | good | written 2026-09-17; PaTT payload-depth pass next | P2 |
| XXE | [[xxe]] | good | OOB / blind / error-based external-DTD library | P2 |
| SSTI | [[ssti]] | strong | bigger per-engine payload lib + sandbox/WAF bypass | P2 |
| Command injection | [[command-injection]] | good | bigger separator/space/keyword-bypass lib; reverse-shell cheat sheet | P1 |
| SSRF | [[ssrf]] | good | IP-encoding/redirect bypass lib + cloud-metadata endpoint table | P2 |
| IDOR / broken access control | [[idor]] | good | method/param/JSON variants, mass-assignment | P2 |
| **Authentication attacks** | [[authentication-attacks]] | good | written 2026-09-17 (hydra/ffuf recipes, enum, bypass, reset); PaTT/PortSwigger pass next | P2 |
| **JWT attacks** | [[jwt-attacks]] | good | written 2026-09-17 (alg:none, HS/RS confusion, crack, kid/jku/jwk) | — |
| **REST / GraphQL API** | [[rest-api]] · [[graphql-api]] · [[api-testing]] | good | written 2026-09-17 (API Top 10 surface + run-book, GraphQL payloads) | — |
| **Open redirect** | [[open-redirect]] | good | written 2026-09-17 (bypass library + OAuth/SSRF chaining) | — |

## Build backlog (priority order)

**P1 — do first**
- ✅ *(done 2026-09-17)* Wrote [[lfi]], [[file-upload]], [[authentication-attacks]] to full
  standard; enriched [[xss]]/[[ssrf]]/[[idor]]/[[ssti]] with the [[pg-construction]] +
  [[pg-fullmoon]] worked examples; ingested the [[colleague-web-wiki]].
- ✅ *(done 2026-09-17)* **Autonomous web-fetch pass** (PaTT + HackTricks → `raw/web/`, sha256
  in manifest): blew out the payload libraries on [[xss]], [[command-injection]],
  [[sql-injection]], [[lfi]], [[file-upload]], [[ssti]], [[xxe]], [[ssrf]],
  [[directory-traversal]] — the "much more payloads" ask.
- ✅ *(done 2026-09-17)* [[sql-injection]] leads with the manual path. **Correction (2026-09-17):
  sqlmap is *allowed* on OSWA — it was wrongly marked prohibited; manual-first is guidance, not a rule.**
- ✅ *(done 2026-09-17)* **Quick-checklist** on every technique page (incl. [[csrf]] /
  [[cors-misconfiguration]] / [[idor]]) + the master [[wstg-checklist]] (all 12 WSTG areas,
  doubling as the coverage tracker).

**P2 — next**
- ✅ *(done 2026-09-17)* Densified [[xxe]]/[[ssti]]/[[ssrf]]/[[directory-traversal]] payload
  libraries (fetch pass); wrote [[jwt-attacks]] and the **REST/GraphQL** set ([[rest-api]],
  [[graphql-api]], [[api-testing]]).
- ✅ *(done 2026-09-17)* [[reverse-shells]] cheat sheet (one-liners + PTY upgrade). Still open:
  a **content-discovery / SecLists** wordlist map, Burp per-technique recipes; SQLite row on
  [[sql-enumeration]].
- ✅ *(done 2026-09-17)* OAuth/OIDC → [[oauth-attacks]] (top WSTG gap closed). Still open: SPA and
  SSO per-target-class methodologies; host-header, request smuggling, deserialization, clickjacking.

**P3 — nice-to-have**
- [[open-redirect]], mass-assignment, request smuggling (low OSWA relevance), Marp revision deck.

## Practice plan & scope validation (2026-09-17)

Researched the public OSWA landscape (the official Exam Guide + 5 reviews + community box lists)
to test this KB's scope. **Result: zero technique gaps for the OSWA exam** — every class the
reviews and the WEB-200 syllabus name (SQLi, XSS, LFI/RFI, traversal, cmdi, IDOR, CSRF, XXE,
CORS, SSTI, SSRF, auth/session) is covered. [[jwt-attacks]], [[oauth-attacks]],
[[deserialization]], [[prototype-pollution]], [[nosql-injection]], [[graphql-api]] and
[[rest-api]] are **beyond OSWA core** (OSWE/HTB-flavoured) — over-coverage; don't over-invest
there *for this exam*.

**Drill plan** (reviewers' consensus; OffSec ships **no** dedicated WEB-200 PG boxes):

- **PortSwigger Web Security Academy** — primary drill ground; labs map 1:1 to XSS, CSRF, CORS,
  SSRF, SSTI, IDOR, traversal, SQLi technique pages.
- **The WEB-200 course exercises + challenge labs** — the closest thing to the exam (unanimous).
- **Community practice boxes:**

  | Box | Platform | Teaches |
  |---|---|---|
  | Hawat · Shakabrah | PG | SQLi→`INTO OUTFILE` webshell · command injection → RCE |
  | Sumo | VulnHub/PG | Shellshock command injection |
  | FunboxEasyEnum | VulnHub/PG | enumeration + file-upload webshell |
  | Inclusiveness | VulnHub/PG | LFI/RFI |
  | Potato | PG/VulnHub | PHP type-juggling auth bypass + LFI |
  | Muddy · Interface | PG Practice | XXE+LFI+WebDAV upload · dompdf RCE (CVE) |
  | Pilgrimage · PC · Soccer · Precious | HTB | `.git`+ImageMagick · SQLi/gRPC · upload+WS-SQLi · pdfkit cmdi *(web foothold only — privesc is out of OSWA scope)* |

  Drop your own writeups of these into `raw/web/` and `ingest` → they become worked examples
  (as [[pg-construction]] / [[pg-fullmoon]] already did).

**Minor OSWA-adjacent gaps these boxes surface** (lower priority than the 0xdf set):
- ✅ *(done 2026-09-17)* **Vulnerable-component → public-CVE/PoC workflow** + **`.git`/source
  disclosure** → [[known-vulnerable-components]] (fingerprint version → CVE → adapt PoC).
- **Shellshock** (CGI/Bash env-var cmdi) → note under [[command-injection]]. PHP type-juggling is
  already on [[authentication-attacks]].
- **WebSocket message injection** (WSTG-CLNT-10) and **gRPC/protobuf API injection** — uncovered,
  low OSWA priority.

## 0xdf HTB gap-analysis (24 web boxes, 2026-09-17)

Confronted the KB against 24 0xdf HTB writeups. **The KB covers the vast majority** — SQLi, XSS,
SSTI, LFI/traversal, SSRF, XXE, file-upload, command-injection, GraphQL, JWT and IDOR all recurred
and are already covered. Confirmed **gaps**, by frequency:

**New pages (2026-09-17):**
- ✅ **Insecure deserialization** ([[deserialization]]) — *the #1 gap, now written full*: per-runtime
  markers/sinks/gadget tools (phpggc, pickle, node `_$$ND_FUNC$$_`, ysoserial, **ysoserial.net
  ViewState + machineKey**) + a leaked-machineKey worked example. ~6 boxes.
- **Prototype pollution** ([[prototype-pollution]]) — 2 boxes (lodash `_.merge` → flag flip / RCE).
- **NoSQL injection** ([[nosql-injection]]) — 2 boxes (`$ne`/`$regex` auth bypass).

**Still to write (confirmed, single-box):**
- **.NET exploitation chain** — ViewState deserialization + **machineKey** Forms-auth ticket
  forgery + **padding oracle** (padbuster) + **SSI injection** (`.shtml`) — HTB *Perspective*.
- **Media-processor file-read / SSRF** (FFmpeg `concat:`/`subfile:`, ImageMagick) — HTB *Overgraph*.
- **Tomcat manager WAR-deploy RCE** foothold — HTB *Tabby*. **Encrypted-JWT (JWE) bypass** →
  extend [[jwt-attacks]] — HTB *Principal*. **CSTI** (AngularJS) — *Overgraph*. Niche: CPRF,
  HMAC-digest oracle, LDAP hijack (HTB *Response*).

**Harden existing pages (thin, no new page):**
- [[lfi]] — blind PHP **filter-chain error-oracle** read (not only RCE); **FastCGI/PHP-FPM** RCE pivot.
- [[ssrf]] — **curl multi-URL** trick (`http:// file:///…`), redirect-follow bypass.
- [[xss]] — `javascript:` URI sink via `location.replace` / open redirect.
- [[file-upload]] — **stacked / parser-differential zip** (validate first member vs extract appended).
- [[command-injection]] — promote the **argument-injection** subsection (`escapeshellarg` doesn't stop it; `git ext::sh`, `nc -e`, `awk`/`sed -e`).
- [[sql-injection]] — `preg_match` first-line-only regex-*validation* bypass.

## Sourcing plan (autonomous fetch — Golden rule 4)

Gaps above get filled from: **PayloadsAllTheThings** (payload libraries — permissive
licence, payloads verbatim OK), **HackTricks** (methodology + payloads for the thin pages),
**PortSwigger Web Security Academy** (theory + the best free **practice** labs — reworded in
our words + cited, never pasted; also your hands-on training ground), the already-ingested
[[owasp-wstg]] (checklist backbone), and the **HTB / PG Practice / CTF web writeups you
drop in** (each becomes a worked example on one technique + one target). All land under
`raw/web/` with provenance and are ingested as **untrusted** data.

## See also

[[web-app-assessment]] · [[web-200-oswa]] · [[overview|the synthesis]]

*Source: [[web-200-oswa]] (WEB-200 syllabus & challenge machines); matrix maintained by lint.*
