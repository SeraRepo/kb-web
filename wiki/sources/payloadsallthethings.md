---
type: source
source_kind: doc-repo
origin: github.com/swisskyrepo/PayloadsAllTheThings (per-topic README.md fetched to raw/web/patt-*.md)
sha256_or_commit: per-file sha256 in manifest (master, retrieved 2026-09-17)
ingested: 2026-09-17
trust: untrusted
derived_pages: [xxe, ssrf, directory-traversal, lfi, file-upload, xss, sql-injection, command-injection, ssti, jwt-attacks, rest-api, graphql-api, oauth-attacks, open-redirect, deserialization]
---

# Source — PayloadsAllTheThings (PaTT)

The community payload reference (github.com/swisskyrepo/PayloadsAllTheThings). Per-technique
`README.md` files are **autonomously fetched** (Golden rule 4) into `raw/web/patt-<topic>.md`
with a provenance header (source URL + retrieval date + sha256), one file per topic, and
mined for the **payload libraries** on our technique pages.

**Trust:** untrusted per our hardening — payloads are transcribed into **inert, labelled
fenced blocks**; nothing is executed, and no host named in the source is ever contacted. Any
weaponised body (web shell, reverse shell, live malware) is **defanged** before it lands in
this OneDrive/Defender-synced vault. Out-of-band / exfil hosts are kept generic
(`ATTACKER_IP`, `ATTACKER_HOST`).

**Character:** exhaustive, breadth-first payload lists organised by injection context and
filter/WAF-evasion class — exactly the "much more payloads" layer the OSWA prep needs.
Payloads are short factual technique strings, reused **with attribution to this slug**; PaTT
is a public payload repository.

**Fetched so far (2026-09-17):** XXE, SSRF, Directory Traversal (this batch). Command
Injection, SSTI, Upload, XSS, LFI, SQLi in the same fetch pass. Each `raw/web/patt-*.md`
line is pinned in the manifest so lint can detect upstream drift.

**Fetch pass complete (3/3, 2026-09-17):** XXE, SSRF, Directory-Traversal, Command-Injection,
SSTI (+JavaScript), Upload, XSS, LFI, SQL-Injection (+ per-DBMS MySQL/MSSQL/Postgres/Oracle/SQLite).
Two files (PaTT SQLite, HackTricks LFI) were Defender-quarantined verbatim on this synced vault
→ defanged extractions saved and marked in-file.

*Integrated into: [[xxe]], [[ssrf]], [[directory-traversal]], [[command-injection]], [[ssti]], [[file-upload]], [[xss]], [[lfi]], [[sql-injection]] (+ [[sql-enumeration]]).*
