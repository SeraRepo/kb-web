---
type: mitigation
title: Context-aware output encoding
lang: en
status: active
owasp_top10: ["A03:2021"]
cwe: ["CWE-79"]
asvs: ["V1.1.2", "V1.2.1", "V1.2.3"]
sources: [web-200-oswa]
updated: 2026-07-31
---

# Context-aware output encoding

Primary defence against [[xss]]: when rendering untrusted data, encode it for the **exact
context** it lands in, so it is treated as text, not markup/code.

- **HTML body** → HTML-entity encode (`<` → `&lt;`).
- **HTML attribute** → attribute-encode and always quote attributes.
- **JavaScript string** → JS/Unicode-escape (HTML-encoding does nothing here — a frequent
  bug).
- **URL** → percent-encode; validate the scheme (block `javascript:`).
- **CSS** → CSS-escape.

The key failure mode is **wrong-context encoding**: HTML-encoding a value that is then
placed inside a `<script>` block or an event handler leaves it exploitable. Prefer a
framework's auto-escaping templating and avoid raw-HTML sinks (`innerHTML`,
`dangerouslySetInnerHTML`, `document.write`); use safe sinks (`textContent`) for DOM.

Pair with [[content-security-policy]] (defence in depth) and `HttpOnly`/[[samesite-cookies|SameSite]]
cookies. *ASVS `V1.2.1` (context-aware output encoding), `V1.2.3` (JS/JSON), `V1.1.2` (encode as the final step).*

*Source: [[web-200-oswa]] modules 5–6.*
