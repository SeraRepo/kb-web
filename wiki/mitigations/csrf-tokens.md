---
type: mitigation
title: Anti-CSRF tokens
lang: en
status: active
owasp_top10: ["A01:2021"]
cwe: ["CWE-352"]
asvs: ["V3.3.2", "V3.5.3"]
sources: [web-200-oswa]
updated: 2026-07-31
---

# Anti-CSRF tokens

Primary defence against [[csrf]]: bind each state-changing request to an **unpredictable,
server-validated secret** the attacker's cross-site page cannot know.

- **Synchronizer token** — server issues a per-session (or per-request) token, embeds it in
  a hidden form field / custom header, and validates it server-side on every state change.
- **Double-submit cookie** — token sent both as a cookie and as a request value; server
  checks they match. Simpler (stateless) but weaker if the attacker can set cookies or under
  subdomain issues.

Per-request tokens beat per-session for sensitive flows. Combine with
[[samesite-cookies|SameSite=Lax/Strict]] (belt-and-braces) and re-authentication for
high-value actions.

Ineffective against [[xss]]: in-origin script can read the token and forge a valid request —
fix the XSS first.

*Source: [[web-200-oswa]] module 7.*
