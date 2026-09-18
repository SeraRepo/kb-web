# kb-web — Web Application Security Audit KB

An LLM-maintained, **offline-readable** knowledge base for offensive web-application
security auditing (OSWA / web-pentest oriented). Built on the "LLM wiki" pattern: the agent
writes and maintains the wiki; you read it in Obsidian and study from it directly —
including where no assistant is allowed (certification exams).

## Layout

- `wiki/` — the knowledge base (you read, the agent writes). Ontology: `techniques/`,
  `methodologies/`, `vulns/`, `mitigations/`, `tools/`, `targets/`, `concepts/`,
  `sources/`, plus `index.md` (catalog / study map), `overview.md`, `log.md`.
- `raw/` — immutable sources you drop in (never edited). `manifest.jsonl` tracks them.
- `CLAUDE.md` — the behavioural contract the agent follows (ontology, page content
  standards, ingest/query/lint, security hardening). **Start here to understand the KB.**
- `.claude/skills/ingest/` — the one-command ingestion skill.
- `llm-wiki.md` — the design brief (idea file) this KB was instantiated from.

## Using it

- **Read / study:** open `wiki/` in Obsidian. Start at `index.md` or the
  `methodologies/web-app-assessment` hub; follow `[[wikilinks]]`; use the graph view.
  Every page is self-contained and works offline.
- **Ingest a source:** drop a file into `raw/` (or clone a repo into `raw/repos/`) and tell
  the agent *"ingère raw/"* → it runs the `ingest` skill (idempotent, manifest-diffed).
- **Query / lint:** ask the agent to answer from the wiki (good answers get filed back), or
  to run a lint pass (dead links, orphans, stale pages, framework coverage).

## Current content

- **OffSec WEB-200 (OSWA)** — fully ingested: 10 technique pages (SQLi, XSS, CSRF, CORS,
  directory traversal, XXE, SSTI, command injection, SSRF, IDOR), the enumeration
  methodology, a tool library, and supporting concepts & mitigations.
- Framework mapping: OWASP Top 10 / CWE / ATT&CK filled; **WSTG & ASVS pending** ingestion
  of those corpora.

## Lineage (reference, not config)

Generated from a reusable kit, kept here for reference: `karpathy-llm-wiki.md` (the original
idea), `llm-wiki.md` (this domain's brief), `setup-llm-wiki-step-by-step.md` (the procedure).
