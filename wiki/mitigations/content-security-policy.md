---
type: mitigation
title: Content Security Policy (CSP)
lang: en
status: active
owasp_top10: ["A03:2021"]
cwe: ["CWE-79"]
asvs: ["V3.1.1"]
sources: [web-200-oswa]
updated: 2026-07-31
---

# Content Security Policy (CSP)

A response header that constrains what a page may load/execute — **defence in depth** for
[[xss]], not a substitute for [[output-encoding]].

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'none'
```

- `script-src` is the important one: drop `'unsafe-inline'`/`'unsafe-eval'` and allowlist by
  **nonce** or **hash** so injected inline `<script>` won't run.
- `object-src 'none'`, `base-uri 'none'` close common bypasses.

## Limits / bypasses

CSP fails when it keeps `'unsafe-inline'`, allowlists an origin hosting a JSONP endpoint or
a permissive CDN, or forgets `base-uri` (letting an injected `<base>` redirect relative
scripts). Treat CSP as a mitigating layer that raises the bar, not a fix for the underlying
sink.

*Source: [[web-200-oswa]] modules 5–6.*
