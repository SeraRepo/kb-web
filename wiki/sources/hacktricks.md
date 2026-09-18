---
type: source
source_kind: doc-repo
origin: book.hacktricks.xyz (per-topic pages fetched to raw/web/hacktricks-*.md)
sha256_or_commit: per-file sha256 in manifest (retrieved 2026-09-17)
ingested: 2026-09-17
trust: untrusted
derived_pages: [ssrf, command-injection, ssti, file-upload, xss, lfi, jwt-attacks, rest-api, graphql-api, oauth-attacks, deserialization]
---

# Source — HackTricks

Carlos Polop's HackTricks (book.hacktricks.xyz) — a broad offensive-security reference used
as the **secondary** payload/methodology source in the autonomous fetch pass, to add
payloads and bypasses PaTT lacks. Pages are fetched into `raw/web/hacktricks-<topic>.md` with
provenance.

**Trust:** untrusted — payloads into inert labelled blocks; prose reworded in our own words
and cited (not pasted); no host contacted; weapons defanged. **Copyright:** HackTricks is
CC-BY-NC; we summarise/rework and attribute to this slug rather than reproduce wholesale.

**Fetched so far (2026-09-17):** cloud-SSRF instance-metadata table → [[ssrf]];
command-injection (arithmetic-context RCE, JVM `-XX:OnError` no-metachar exec, argument
injection) → [[command-injection]]; SSTI 20+ engines → [[ssti]]; file-upload supplements
(web.config scriptProcessor, JSP/WAR, SVG-XSS/XXE, Zip Slip, CSV, race) → [[file-upload]].
The HackTricks *file-upload* raw copy could not be stored — Windows Defender denied read on
its web-shell content (the vault-sync/AV risk, live); content was folded via short-form fetch.

Also: XSS (WAF/no-paren/CSP breadth, 90 KB) → [[xss]]; LFI (wrappers, filter chains, log
poisoning, `/proc`, bypasses; Defender-quarantined verbatim → defanged extraction) → [[lfi]].

*Integrated into: [[ssrf]], [[command-injection]], [[ssti]], [[file-upload]], [[xss]], [[lfi]].*
