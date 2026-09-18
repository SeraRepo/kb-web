# Overview — Web Application Security Audit KB

The synthesis to revise from: how the pieces fit, what matters most, and the traps. Read it
end-to-end before an exam; drill into pages via the links.

## The one mental model: input → sink

Almost every finding is *untrusted input reaching a dangerous sink without the right
guard*. Assessment is therefore: **enumerate every input, identify what sink each feeds,
and test the matching class.** That triage is the spine of [[web-app-assessment]].

## Two families

**Injection — input reaches an interpreter.** The guard is *keep data out of the code
plane* (parameterise / encode / disable features):

- [[sql-injection]] → the SQL parser · [[command-injection]] → an OS shell ·
  [[ssti]] → a template engine · [[xss]] → the victim's JS engine ·
  [[xxe]] → an XML parser.
- Recurring trap: **context decides the payload** — SQLi in an `ORDER BY` (no UNION,
  error-based instead), XSS in an attribute vs a JS string, SSTI per engine. Fingerprint,
  then pick the escape.

**Broken access control / trust — the server trusts something it shouldn't.** The guard is
*check authorization on every object and origin*:

- [[idor]] → trusts a client-supplied object reference · [[csrf]] → trusts ambient cookies ·
  [[cors-misconfiguration]] → trusts an attacker origin · [[directory-traversal]] → trusts a
  client-supplied path.

## Chaining (where the real impact is)

- [[xxe]] → [[ssrf]] (external entity fetches an internal URL)
- [[sql-injection]] / [[directory-traversal]] → RCE (file write / LFI → web shell)
- [[ssti]] / [[command-injection]] → reverse shell (catch with [[netcat]])
- [[xss]] runs *in-origin* → defeats [[csrf]] tokens
- [[ssrf]] → cloud metadata credentials → account/infra takeover
- [[idor]] → mass data exposure

## Recurring exam traps

- **Confirm by hand before automating** — [[sqlmap]]/[[ffuf]] miss context-specific bugs.
- **Read the error** — it leaks DBMS, engine, language, query structure.
- **Encodings & filters** — URL/double-URL/`..%2f`, comment/case tricks; a filter that
  strips `../` once is beaten by `....//`.
- **Enumerate exhaustively** — most "stuck" moments are a missed endpoint or parameter
  ([[cewl]] + [[ffuf]]/[[gobuster]] + [[nmap]]).
- **Two accounts** make access-control bugs ([[idor]]) obvious.

## Defensive throughline

Parameterise ([[parameterized-queries]]), encode in context ([[output-encoding]] +
[[content-security-policy]]), validate/allowlist inputs and origins, enforce
authorization per object, disable dangerous parser features, and run least-privilege.
Map each finding's fix to the relevant ASVS 5.0 requirement (on each page's frontmatter).

## How to study from this KB

Start here → the [[web-app-assessment]] run-book → each [[sql-injection|technique]] page
(self-contained: mechanism → detection → exploitation → worked example → remediation) →
the [[nmap|tool]] pages for command syntax. Everything works offline in Obsidian; follow
the inline wiki-links and use the graph view.
