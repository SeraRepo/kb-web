# Log

Append-only record of every operation. One entry per op, prefixed
`## [YYYY-MM-DD] ingest|query|lint | <title>` so it stays greppable:

```bash
grep "^## \[" log.md | tail -5
```

---

## [2026-07-31] ingest | WEB-200 (OSWA) — SQL & SQL Injection (modules 8–9)

- Source: [[web-200-oswa]] (guide, untrusted, licensed personal copy). sha256 pinned in manifest.
- Created: [[sql-injection]] (active) with the Piwigo error-based-via-`ORDER BY` case study as worked example; [[sql-enumeration]] (active, per-DBMS), [[sqlmap]] (active).
- Stubs created for linked pages: [[burp-suite]], [[parameterized-queries]], [[web-app-assessment]], [[command-injection]].
- Framework mapping: A03:2021, CWE-89, ATT&CK T1190. **WSTG/ASVS deliberately left empty** — pending ingestion of the OWASP WSTG + ASVS corpora (no unverified IDs).
- Format sign-off obtained; batching remaining modules next.

## [2026-07-31] ingest | WEB-200 (OSWA) — XSS & Cross-Origin (modules 5–7)

- Created techniques: [[xss]] (Shopizer reflected-XSS-via-`ref` worked example), [[csrf]] (OFBiz `createUserLogin` + missing-SameSite worked example), [[cors-misconfiguration]] (reflected-origin / bad-allowlist).
- Concepts: [[same-origin-policy]], [[samesite-cookies]]. Mitigations: [[output-encoding]], [[content-security-policy]], [[csrf-tokens]].
- Framework: XSS A03:2021/CWE-79; CSRF A01:2021/CWE-352; CORS A05:2021/CWE-942. WSTG/ASVS pending.
- Cross-links: XSS defeats CSRF tokens; CORS can leak CSRF tokens; SameSite/SOP tie the three together.

## [2026-07-31] ingest | WEB-200 (OSWA) — Directory Traversal & XXE (modules 10–11)

- Created techniques: [[directory-traversal]] (Home Assistant config-file read; `../`, URL-encoding bypasses), [[xxe]] (OFBiz XML-import `entity-engine-xml` blind/stored file read). Concept: [[xml-entities]].
- Created [[ssrf]] as a stub (referenced by [[xxe]] via external-entity `http://`; fleshed in module 14).
- Framework: traversal A01:2021/CWE-22; XXE A05:2021/CWE-611. WSTG/ASVS pending.

## [2026-07-31] ingest | WEB-200 (OSWA) — SSTI (module 12)

- Created [[ssti]] (Twig/Freemarker/Pug/Jinja/Handlebars as sections; Craft CMS + Sprout Forms and Halo case studies) and concept [[templating-engines]].
- Framework: A03:2021, CWE-1336/CWE-94, ATT&CK T1190. WSTG/ASVS pending.

## [2026-07-31] ingest | WEB-200 (OSWA) — Command Injection, SSRF, IDOR (modules 13–15)

- Fleshed [[command-injection]] (ONA `xajax` ping `;id` → `passthru()` RCE; payloads **defanged** for AV/OneDrive safety) and [[ssrf]] (Group Office `url` param on `/api/upload` → access-log confirm → `file:///etc/passwd` via `/api/download.php`). Created [[idor]] (OpenEMR `noteid` iteration).
- Framework: cmdi A03:2021/CWE-78/T1190; SSRF A10:2021/CWE-918; IDOR A01:2021/CWE-639. WSTG/ASVS pending.
- All technique modules (5–15) now ingested. Remaining: methodology (mod 3+16), Burp (mod 4), and fleshing the [[parameterized-queries]] stub.

## [2026-07-31] ingest | WEB-200 (OSWA) — methodology, Burp, mitigations (modules 3, 4, 16)

- Fleshed [[web-app-assessment]] (baseline hub run-book linking all technique pages), [[burp-suite]] (Proxy/Repeater/Intruder/Comparer/Decoder/Collaborator), and [[parameterized-queries]].
- **WEB-200 fully ingested.** No draft pages remain. Totals: 10 techniques, 5 concepts, 2 tools, 4 mitigations, 1 methodology, 1 source.
- Follow-ups for next sources: OWASP WSTG + ASVS corpora (to fill `wstg`/`asvs` IDs), and `targets/` pages (SPA/API, GraphQL, SSO/OAuth, WebSocket).

## [2026-07-31] query | Tool library — standard web-pentest tools

- Created tool pages (purpose · install · command cheat-sheet · mapping to techniques · limits): [[nmap]], [[ffuf]], [[gobuster]], [[wfuzz]], [[cewl]], [[hydra]], [[netcat]], [[curl]], [[nikto]]. [[burp-suite]] + [[sqlmap]] already existed.
- Course-derived pages cite WEB-200 (nmap/ffuf/gobuster/cewl/netcat); the rest are general-reference cheat-sheets built at the user's request (`sources: []`).
- Wired all tools into [[web-app-assessment]] (enumeration/credential/exploitation phases) and the index Tools section.

## [2026-07-31] lint/enrich | Page-by-page enrichment + overview synthesis

- Enriched all 10 technique pages with missing depth: SQLi (auth-bypass / second-order / WAF-evasion), XSS (DOM sources→sinks), CSRF (login/JSON variants), CORS (subdomain + postMessage), directory-traversal (LFI→RCE wrappers/log-poisoning), XXE (file-upload SVG/OOXML + blind OOB DTD), SSTI (Velocity/Smarty/ERB + sandbox/blind), command-injection (argument injection), SSRF (cloud metadata + IP/DNS bypasses), IDOR (BOLA / mass-assignment). Tool cross-links added throughout.
- Wrote [[overview]] synthesis (input→sink model, injection vs access-control families, chaining map, exam traps, defensive throughline).
- Repo hygiene: `.gitattributes` (LF normalization) + `README.md` realigned to the web-audit KB.

## [2026-07-31] ingest | OWASP WSTG + ASVS 5.0 — framework ID mapping

- Ingested [[owasp-wstg]] (test IDs from `checklists/checklist.md`) and [[owasp-asvs]] (v5.0.0). Both untrusted ZIP snapshots (no commit to pin).
- Filled **verified** `wstg` (10 techniques) and `asvs` (10 techniques + 4 mitigations) frontmatter IDs — every ID matched against the corpus, none guessed. ASVS 5.0's reorganised scheme confirmed the earlier call not to assert 4.0 IDs from memory.
- Cleared all "pending" notes; recorded the ASVS 5.0 CSRF framing (SameSite/Sec-Fetch, not tokens) and the identifier/`ORDER BY`-can't-be-escaped point. Added ASVS column to the index Dataview.

## [2026-09-17] setup | OSWA exam track — coverage matrix + autonomous-fetch policy

- **Contract change (owner-authorized):** Golden rule 4 flipped from "never auto-fetch" to **web fetching allowed** into `raw/web/` with provenance; fetched content stays **untrusted** (rules 1–2), payloads inert (rule 3), never contact a host named in a source. Updated `CLAUDE.md` (rule 4 + Lint line), `.claude/skills/ingest/SKILL.md`, and the `llm-wiki.md` brief (2 lines) to match.
- **New:** [[oswa-exam]] methodology — exam constraints (manual-first, sqlmap/scanners restricted, offline), OSWA web-target attack flow, **coverage matrix** (WEB-200 topic → page → density → gap → priority), and a prioritised **build backlog**. Now the study spine; linked from [[index]].
- **Draft stubs created** (gaps the matrix surfaces): [[lfi]], [[file-upload]], [[authentication-attacks]], [[jwt-attacks]], [[open-redirect]] — frontmatter + one-line scope + `status: draft`, linked into the graph. Added to the index Techniques list with `(draft)` markers.
- Density audit of existing pages: SQLi/SSTI **strong**; XSS/traversal/cmdi/XXE/SSRF/IDOR/CORS/CSRF **good**; [[sql-enumeration]] already a real per-DBMS cheat sheet (missing SQLite + WAF-bypass). Core OSWA gap = **payload-library breadth + checklists + the 3 P1 stubs**, not structure.
- No web fetched yet (next step); no source hashes changed → `manifest.jsonl` untouched.

## [2026-09-17] ingest | PG walkthroughs (Construction, Fullmoon) + colleague web-wiki — P1 pages

- Sources (untrusted): [[pg-construction]] + [[pg-fullmoon]] (OffSec PG writeups, `raw/web/`, sha256 pinned) and [[colleague-web-wiki]] (227-file WSTG/API-mapped wiki, `raw/repos/web-main-wiki.zip`, sha256 pinned). Extracted to scratchpad for reading; `raw/` kept immutable.
- **P1 pages written to full standard** (replaced draft stubs): [[lfi]] (php wrappers, filter-chain RCE, log/session poisoning, RFI), [[file-upload]] (ext/content-type/magic-byte/`.htaccess`/traversal bypass, Zip Slip, defanged web shell), [[authentication-attacks]] (default creds, enumeration, hydra/ffuf brute with CSRF handling, lockout/IP-rotation bypass, auth bypass, reset flaws). Payloads inert; web shells **defanged** (OneDrive/Defender).
- **Enriched with walkthrough worked examples:** [[xss]] (blind stored XSS → admin/localhost weaponisation → RCE), [[ssrf]] (`0.0.0.0` loopback bypass + SSRF→IDOR screenshot chain), [[idor]] (predictable-filename IDOR; 403≠access-control), [[ssti]] (**EJS** engine added + regex-replace-once keyword-filter bypass by nesting).
- Colleague wiki mined for **offensive nuggets only** (WSTG-ATHZ-01 / BUSL-08-09 / ATHN-04) + cited for remediation; its broad backlog (JWT, open-redirect, prototype-pollution, deserialization, API/GraphQL, concepts) recorded on [[colleague-web-wiki]] for later.
- Framework IDs verified: LFI CWE-98/A03·A01/WSTG-ATHZ-01; upload CWE-434/WSTG-BUSL-08·09; auth A07/CWE-287·307/WSTG-ATHN-02·04·09·IDNT-04. **ASVS left `[]`** — colleague IDs must be re-verified against our ASVS corpus before asserting (Golden rule 5).
- Manifest +3 lines. Index + [[oswa-exam]] coverage matrix refreshed (3 P1 rows stub→good; P1 backlog item marked done, next = autonomous PaTT/HackTricks/PortSwigger payload-depth pass).

## [2026-09-17] ingest | Autonomous fetch pass (batch 1/3) — PaTT/HackTricks payload libraries: XXE, SSRF, traversal

- **Autonomous web fetch** (Golden rule 4, via subagent): PayloadsAllTheThings XXE / SSRF / Directory-Traversal READMEs + HackTricks cloud-SSRF → saved to `raw/web/patt-*.md` + `raw/web/hacktricks-cloud-ssrf.md` (provenance headers, sha256 pinned, untrusted). Nothing executed; no host / metadata IP contacted; OOB hosts kept generic; weapons defanged.
- New source pages: [[payloadsallthethings]], [[hacktricks]].
- **Payload libraries added** (inert): [[xxe]] (`php://filter`/`data://`, XInclude, OOB external-DTD, **local-DTD error-based** (no outbound), SVG/OOXML upload, UTF-16 WAF bypass), [[ssrf]] (loopback / IP-encoding / parser-confusion / scheme bypasses + expanded cloud-metadata table: AWS IMDSv1-v2/ECS/Lambda, GCP, Azure, DO, Alibaba, Oracle), [[directory-traversal]] (climb+encoding ladder incl. overlong-UTF-8, `..;/`; Linux+Windows target-file lists). **Quick-checklist** added to each.
- Manifest +4 lines; index sources refreshed. Batches 2 (cmdi/SSTI/upload) & 3 (XSS/LFI/SQLi) pending — agents running.

## [2026-09-17] ingest | Autonomous fetch pass (batch 2/3) — command injection, SSTI, file upload

- Autonomous fetch (subagent): PaTT command-injection / SSTI (+JavaScript) / Upload + HackTricks command-injection / SSTI → `raw/web/` (provenance, sha256, untrusted; weapons defanged). **Note:** the HackTricks *file-upload* README could **not** be saved — Windows Defender denied read on its web-shell content (the OneDrive/Defender risk, live); folded via short-form fetch instead.
- **Payload libraries + quick-checklists:** [[command-injection]] (separators, `${IFS}`/brace space bypass, quote/wildcard/slash-free keyword bypass, blind time/DNS-OOB, Windows `%VAR:~%`/caret, polyglot), [[ssti]] (error→language oracle + Jinja globals gadgets, Mako/Tornado/Nunjucks/SpringEL/Thymeleaf/Pebble/Razor/ASP/Go engines), [[file-upload]] (alt-ext lists, NTFS ADS, **config-file RCE** `.htaccess`/`web.config`/`uwsgi.ini`/`.pth`/`package.json`, path-in-filename & second-order, SVG-XSS/XXE/Zip-Slip/CSV, ImageTragick/CVE-2022-44268).
- Manifest +6 lines; [[hacktricks]] derived_pages extended. Batch 3 (XSS/LFI/SQLi) pending — agent running.

## [2026-09-17] ingest | Autonomous fetch pass (batch 3/3) — XSS, LFI/RFI, SQLi

- Autonomous fetch (subagent): PaTT XSS / File-Inclusion / SQL-Injection (+ per-DBMS MySQL/MSSQL/Postgres/Oracle/SQLite) + HackTricks XSS/LFI → `raw/web/` (provenance, sha256, untrusted; weapons defanged). Two files (HackTricks LFI, PaTT SQLite) were **Defender-quarantined verbatim** on the synced vault → defanged extractions saved. Nothing executed; no host contacted.
- **Payload libraries + quick-checklists:** [[xss]] (per-context vectors, WAF / no-parentheses / CSP evasion, defanged exfil PoCs), [[lfi]] (`php://filter` chains + **php_filter_chain** no-write RCE, extra log/session targets, pearcmd, renderer LFI, `assert()`), [[sql-injection]] (detect/fingerprint, auth-bypass, error/boolean/time **per-DBMS**, OOB/stacked, WAF-evasion classes). **SQLi reframed manual-first — sqlmap flagged OSWA-prohibited on targets.**
- Manifest +10 lines; [[payloadsallthethings]] + [[hacktricks]] derived_pages extended. **Autonomous fetch pass complete (3/3): 8 technique payload libraries + quick-checklists across 9 pages.**

## [2026-09-17] query | WSTG master checklist + remaining technique checklists

- Created [[wstg-checklist]] — a printable test-plan across all **12 WSTG v4.2 areas (115 IDs)**, each row linking the KB technique page or marking a coverage gap; doubles as the offline study map + WSTG coverage tracker (IDs verified vs [[owasp-wstg]]).
- Added quick-checklists to [[csrf]], [[cors-misconfiguration]], [[idor]] — **every technique page now carries a detect→exploit→confirm checklist**.
- Coverage-gap backlog surfaced: OAuth (ATHZ-05), host-header (INPV-17), request smuggling (INPV-15/16), deserialization (INPV-23), prototype pollution (INPV-22), clickjacking (CLNT-09), API/GraphQL (APIT) — several draftable from [[colleague-web-wiki]].
- index Methodologies refreshed; [[oswa-exam]] backlog checklist item closed.

## [2026-09-17] ingest | JWT + REST/GraphQL API set (fetch + colleague-KB mining)

- Autonomous fetch (subagent): PaTT JWT / GraphQL / API-Key-Leaks + HackTricks JWT / GraphQL / web-API → `raw/web/` (provenance, sha256, untrusted). No defang needed — no live weapons in these sources. **Speculative / future-dated CVEs** in the fetched HackTricks copy were **not asserted** (untrusted, unverifiable); only canonical CVE classes kept (Golden rule 5).
- Wrote [[jwt-attacks]] (stub → full): `alg:none`(+case)/null-sig, HMAC secret crack (`hashcat -m 16500`), **HS/RS key confusion**, embedded `jwk`, `kid` traversal/SQLi/SSRF, `jku`/`x5u` JWKS spoofing, cross-JWT substitution — inert forged-header library + remediation.
- **`targets/` populated** (was empty): [[rest-api]] (OWASP API Top 10 surface + request-tampering toolkit; BOLA/mass-assignment → [[idor]], BFLA/`CWE-285`, SSRF, Content-Type→XXE) and [[graphql-api]] (detection, full introspection query, field-suggestion recovery, batching/aliasing, resolver injection, per-resolver authz, DoS/CSRF).
- New methodology [[api-testing]] (run-book by API Top 10). Mined [[colleague-web-wiki]] (api-testing, rest-graphql-api, wstg-sess-10/apit-99, jwt-security/graphql-security, api5/BFLA) for structure + remediation.
- index Targets populated; [[wstg-checklist]] APIT rows + SESS-10 linked; [[oswa-exam]] matrix +2 rows (JWT, API), P2 backlog updated. Manifest +6 lines; source derived_pages extended.

## [2026-09-17] ingest | OAuth 2.0 / OIDC attacks (WSTG-ATHZ-05)

- Autonomous fetch (subagent): PaTT OAuth-Misconfiguration + HackTricks OAuth-to-account-takeover → `raw/web/` (provenance, sha256, untrusted; nothing run, no AS/host contacted; **no CVEs asserted**). The HackTricks copy is a **structured transcription** (the fetch declined byte-verbatim on copyright) — noted in the manifest.
- Wrote [[oauth-attacks]] (new, closes the **top WSTG coverage gap**): flow primer (auth-code+PKCE, 3 actors), recon (`.well-known`), and the attack set — **`redirect_uri` theft → account takeover** (bypass catalogue), missing/weak-`state` login-CSRF & forced account-linking, PKCE downgrade / open dynamic registration, implicit token leakage, `response_mode`/scope juggling, **OIDC token & claim confusion** (aud/iss/nonce, email-confusion), `request_uri`/`jku` IdP SSRF, **mix-up & 307 credential leak** (RFC 9700), pre-ATO / `prompt=none` / clickjacking, `client_secret` leak & code-reuse rules, `redirect_uri`/`state` XSS — + RFC 9700 remediation + checklist.
- Mined [[colleague-web-wiki]] (wstg-athz-05, oauth-security RFC 9700, federated-identity concept).
- index Techniques + [[wstg-checklist]] ATHZ-05 + [[oswa-exam]] refreshed. Manifest +2 lines; source derived_pages extended.

## [2026-09-17] lint/enrich | ASVS verification + open-redirect page (hygiene)

- **ASVS 5.0 requirement IDs verified against our corpus** (`raw/repos/ASVS-master/5.0/en/`, never guessed — Golden rule 5) and applied to the pages previously left `asvs: []`: [[jwt-attacks]] (V9.1.1/9.1.2/9.1.3/9.2.3 — ASVS 5.0 has a dedicated **V9 Self-contained Tokens** chapter), [[oauth-attacks]] (V10.4.1/10.4.6/10.2.1/10.2.2/10.5.1 — dedicated **V10 OAuth and OIDC** chapter), [[file-upload]] (V5.2.2/5.3.1/5.3.3), [[lfi]] (V5.3.2), [[authentication-attacks]] (V6.3.1/6.3.2/6.3.8/6.4.3), [[rest-api]] (V4.1.3/4.1.4), [[graphql-api]] (V4.3.1/4.3.2). Colleague-KB ASVS hints were re-checked, not trusted.
- Wrote [[open-redirect]] (stub → full): server + client sinks, bypass library (`//`, `/\`, `@`, `#`, subdomain/suffix, encoded), `javascript:`→[[xss]] escalation, OAuth token-theft / SSRF chaining, remediation (ASVS **V3.7.2** verified).
- [[owasp-asvs]] source: mapping table + derived_pages extended (8 pages); index/[[oswa-exam]] refreshed. **No draft pages remain in the KB; no session-authored page carries an unexplained `asvs: []`.**

## [2026-09-17] query | Reverse shells & TTY-upgrade cheat sheet

- Created [[reverse-shells]] — post-exploitation cheat sheet: listeners (nc/ncat/socat/pwncat), Linux + Windows reverse/bind one-liners (bash `/dev/tcp`, sh, nc `-e`/mkfifo, python-pty, perl, php, ruby, socat, awk; PowerShell TCPClient), firing through a web sink (stager `curl|bash` / base64), and the **dumb-shell → full-PTY upgrade** (`python -c pty.spawn`, `stty raw -echo; fg`, `reset`, socat/pwncat). Web-shell bodies **defanged**; every host is an `ATTACKER_IP/PORT` placeholder. **Verified not Defender-quarantined on write** (the KB's highest AV-risk page). General-reference (`sources: []`).
- Wired inbound links from [[command-injection]] (Getting a shell) and [[oswa-exam]] (Foothold phase); added to index Techniques; [[oswa-exam]] backlog item closed.

## [2026-09-17] lint | 0xdf HTB gap-analysis (24 web boxes) — confirmed coverage gaps

- Autonomous web fetch (3 subagents): analysed **24 0xdf HTB writeups** against the KB coverage list; writeups treated as **untrusted** (extraction only, no host contacted, nothing saved to `raw/` — this was analysis, not ingestion).
- **Result:** the KB covers the vast majority — SQLi/XSS/SSTI/LFI/traversal/SSRF/XXE/upload/cmdi/GraphQL/JWT/IDOR all recurred and are covered. Gaps ranked by frequency.
- **New draft stubs** for the top recurring gaps: [[deserialization]] (WSTG-INPV-23 / CWE-502 — **#1**, ~6 boxes across Node/Python/PHP/.NET), [[prototype-pollution]] (INPV-22 / CWE-1321, 2 boxes), [[nosql-injection]] (CWE-943, 2 boxes). Wired into [[wstg-checklist]] (INPV-05/22/23) + index Techniques.
- Full frequency report + "still to write" (.NET chain: ViewState/machineKey/padding-oracle/SSI; FFmpeg media-processor; Tomcat WAR-deploy; JWE bypass; CSTI; niche CPRF/HMAC-oracle/LDAP) + "harden-thin" list (lfi filter-chain-oracle/FastCGI, ssrf curl-multi-URL, xss `javascript:` sink, upload stacked-zip, cmdi argument-injection promote, sqli preg_match bypass) filed in [[oswa-exam]] (§ 0xdf HTB gap-analysis).

## [2026-09-17] ingest | Insecure deserialization — full page (fills the #1 0xdf gap)

- Autonomous fetch (subagent): PaTT Insecure-Deserialization (README + PHP/Java/Python/DotNET/Ruby) + HackTricks deserialization + `__VIEWSTATE` → `raw/web/` (9 files, provenance, sha256, untrusted; **none Defender-quarantined**). The agent flagged and **discarded a WebFetch-fabricated "Node.md"** (PaTT has no Node file) — Node content sourced from HackTricks (untrusted-data discipline held).
- Wrote [[deserialization]] (stub → full): runtime-identifier table (magic bytes/markers/where the blob lives), per-runtime **sink + gadget tool** (PHP `phpggc`/PHAR, Python pickle `__reduce__`, Node `_$$ND_FUNC$$_` IIFE, Java `ysoserial`, **.NET `ysoserial.net` ViewState with machineKey/validationkey/decryptionkey flags**, Ruby Marshal), a **leaked-machineKey ViewState worked example**, remediation (ASVS **V1.5.2** verified vs our corpus; + V1.3.2 eval / V1.3.8 JNDI) + checklist. Gadget **blobs kept OFF the vault** (markers + `<CMD>` placeholders); page verified not AV-quarantined on write.
- index + [[wstg-checklist]] (INPV-23) → active; [[owasp-asvs]] mapping (V1.5.2) + derived_pages extended; manifest +9 lines. Remaining 0xdf gaps (prototype-pollution, nosql-injection, .NET machineKey/padding-oracle/SSI, FFmpeg, Tomcat WAR, JWE, CSTI) tracked in [[oswa-exam]].

## [2026-09-17] lint | OSWA scope validation + exam-fact correction (official guide + 5 reviews)

- Autonomous web research (3 subagents): official OffSec OSWA/WEB-200 **Exam Guide + FAQ**, 5 exam **reviews**, and community **practice-box lists**. Untrusted-data discipline; **no exam solutions/dumps sought** (NDA).
- **CORRECTION — factual error fixed:** earlier entries/pages claimed "sqlmap / automated exploitation are prohibited on OSWA targets." **Wrong.** The official Exam Guide **allows** sqlmap, Tplmap, Nikto, Burp, `msfvenom`, `ysoserial`; it **bans** only spoofing, commercial/enterprise tools (Metasploit Pro, Burp Enterprise), auto-exploitation frameworks (`db_autopwn`/`browser_autopwn`), mass scanners (Nessus/OpenVAS/NeXpose/…), and AI/LLMs. Fixed in [[oswa-exam]], [[wstg-checklist]], [[sql-injection]] (×2), [[lfi]]. *(Historical entries above — "sqlmap flagged OSWA-prohibited" — stand as written per the append-only rule; this entry is the correction of record.)* Manual-first is kept as **guidance** (sqlmap is noisy / often fails), not a rule.
- **Authoritative exam facts** added to [[oswa-exam]]: **5 targets**, 10 pts/flag (`local.txt`+`proof.txt`), **70/100 to pass**, 23h45m + 24h report, proctored / Kali-OpenVPN, **no priv-esc required**, AI/LLM banned.
- **Scope validation: zero OSWA technique gaps** — the KB covers every class the reviews / WEB-200 syllabus name; [[jwt-attacks]]/[[oauth-attacks]]/[[deserialization]]/[[prototype-pollution]]/[[nosql-injection]]/[[graphql-api]]/[[rest-api]] are **over-coverage** (OSWE/HTB-flavoured). Added a **practice/drill plan** (PortSwigger Academy + course labs + community boxes: Hawat/Sumo/Shakabrah/FunboxEasyEnum/Inclusiveness/Potato/Muddy/Interface + HTB Pilgrimage/PC/Soccer/Precious) to [[oswa-exam]].
- Minor OSWA-adjacent gaps noted (low priority): vulnerable-component→public-CVE/PoC workflow, `.git` source disclosure, Shellshock, WebSocket/gRPC injection.

## [2026-09-17] query | Known-vulnerable components (fingerprint → CVE → PoC) page

- Created [[known-vulnerable-components]] (**A06:2021** / `CWE-1104` / WSTG-INFO-08-09): the recon-to-exploit workflow — precise **version fingerprinting** (headers/meta/files/favicon/`whatweb`), **`.git`/VCS/backup source disclosure** (`git-dumper`), **CVE/PoC lookup** (`searchsploit`/NVD/GHSA; with an OSWA note that mass scanners are banned but `searchsploit`/targeted lookup are fine), read-adapt-confirm, + a recurring-example table (dompdf CVE-2022-28368, ImageMagick CVE-2022-44268, pdfkit CVE-2022-25765, Tiny File Manager CVE-2021-45010, GitPython CVE-2022-24439 — from the practice-box research). **Closes two OSWA-adjacent gaps** (component-CVE workflow + `.git` disclosure) in one page.
- Wired into [[web-app-assessment]] (recon), [[wstg-checklist]] (INFO-09, CONF-04), index Techniques; [[oswa-exam]] backlog items marked done.

## [2026-09-17] query | OSWA box attack playbook (detailed roadmap / checklist)

- Created [[oswa-box-playbook]] — a check-as-you-go run-book for a single OSWA-type target: **Phase 0** recon (nmap/whatweb/feroxbuster/nikto commands), **Phase 1** enumerate (map every endpoint/input/version, `.git`/source disclosure, two accounts), **Phase 2** a **per-input triage table** (input signal → first probe → technique page → tool, covering all ~17 classes), **Phase 3** exploit → foothold → flags (`local.txt` via the app, `proof.txt` on disk, **no priv-esc**), **Phase 4** document-as-you-go — plus a **"when I'm stuck" checklist** and a quick command reference. Every step links the technique/tool page. Synthesised from [[web-200-oswa]] + the OSWA exam-review & HTB/PG box research.
- Linked from index Methodologies and [[oswa-exam]] (attack-flow section).
