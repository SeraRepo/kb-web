---
type: technique
title: Open redirect
lang: en
status: active
wstg: ["WSTG-CLNT-04"]
owasp_top10: ["A01:2021"]
owasp_api: []
asvs: ["V3.7.2"]
cwe: ["CWE-601"]
attack: []
cvss: ""
sources: [payloadsallthethings, colleague-web-wiki]
updated: 2026-09-17
---

# Open redirect

**TL;DR** — The app takes a redirect destination from user input and sends the browser there
without validating it. Low impact alone (phishing that borrows the real site's credibility), but
a valuable **primitive**: it exfiltrates OAuth `code`/tokens, bypasses SSRF/`redirect_uri`
allowlists, and — when the sink drops the scheme — escalates to [[xss|DOM XSS]].

> Framework: **A01:2021 – Broken Access Control**, `CWE-601` (URL redirection to untrusted
> site). WSTG `WSTG-CLNT-04`; ASVS `V3.7.2` (auto-redirect only to an allowlisted host).

## Where it applies

Post-login `?next=`/`?returnUrl=`/`?redirect=`/`?url=`/`?dest=`/`?continue=` parameters, logout
redirects, OAuth `redirect_uri` ([[oauth-attacks]]), language/region switchers, "back to" links,
and any tracking/link-wrapper. Both **server-side** (`Location:` header from input) and
**client-side** (input flows into `location`/`location.href`/`location.assign`/`replace` or
`<meta http-equiv=refresh>`).

## How it works

```php
header("Location: " . $_GET['url']);          // server-side sink
```
```js
var r = location.hash.substring(1);           // client-side sink (DOM)
window.location = 'https://' + decodeURIComponent(r);
```
If the client sink drops the `https://` prefix (`window.location = decodeURIComponent(r)`), a
`javascript:` value executes → DOM [[xss]].

## Detection

Set the parameter to an external host and confirm the browser follows it. Then try the bypasses
below against any allowlist, and a `javascript:`/`data:` value against a client-side sink.

## Payload / bypass library

Inert; target the app `trusted.com`, attacker `evil.com`.

```text
https://evil.com                     # naive: any absolute URL accepted
//evil.com                           # protocol-relative — bypasses "must start with /" checks
/\evil.com     /\/evil.com           # backslash/mixed — browsers normalise to //evil.com
https:evil.com   https:/evil.com     # missing/single slash
https://trusted.com@evil.com         # @-userinfo: real host is evil.com
https://evil.com#trusted.com         # fragment — allowlist substring-matches trusted.com
https://evil.com?trusted.com         # query — same trick
https://evil.com\.trusted.com        # backslash confuses the parser
https://trusted.com.evil.com         # suffix / subdomain trust
https://trusted.evil.com             # prefix / substring trust
https://evil.com/trusted.com         # path contains the allowlisted string
https://trusted%00.evil.com          # null / control-char injection
https://trusted。com  (IDN 。)        # unicode dot / homograph
%2f%2fevil.com   %5c%5cevil.com       # URL-encoded // or \\
```
Client-side sink → escalate to [[xss]]:

```text
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
```
Header-based → CRLF (`%0d%0a`) can also split the response (header injection).

## Chaining — why it matters

- **OAuth token/`code` theft:** an open redirect on an allowlisted host lets a loose
  `redirect_uri` bounce the authorization response to the attacker → account takeover
  ([[oauth-attacks]]).
- **SSRF allowlist bypass:** the server's fetch allowlist trusts `trusted.com`, which has an
  open redirect to an internal URL ([[ssrf]]).
- **Filter/WAF bypass & phishing:** the URL bar shows the real domain; victims trust the link.

## Worked example — `?returnUrl=` on login

A login page redirects to `?returnUrl=/dashboard` after auth. `?returnUrl=https://evil.com`
sends the freshly-authenticated user to the attacker (phishing a re-login). The allowlist
"starts with `/`" is beaten by `?returnUrl=/\evil.com` (browser reads it as `//evil.com`), and
`?returnUrl=https://login.trusted.com.evil.com` beats a naive "contains `trusted.com`" check.

## Confirming impact

Show the browser navigating from the trusted origin to your host (or the `javascript:`
escalation firing). On its own: **Low** (phishing aid); chained into OAuth ATO or SSRF: as high
as the chain reaches.

## Remediation

- Don't take the destination from the user — **fixed server-side targets**, or an **indirect
  reference** (a short id mapped server-side to an allowlisted URL).
- If a dynamic target is unavoidable: **allowlist** exact hosts, force **same-site/relative**
  targets, reject absolute and protocol-relative (`//`, `/\`) URLs, and never assign untrusted
  data straight to `location` (ASVS `V3.7.2`). Optionally show an interstitial (`V3.7.3`).
  (Control set: [[colleague-web-wiki|open-redirect-prevention]].)

## Quick checklist

- [ ] Any `next`/`returnUrl`/`redirect`/`url`/`dest` param, or a client-side `location` sink?
- [ ] External host followed? → try `//evil`, `/\evil`, `@`, `#`, `.evil.com`, encoded `%2f%2f`.
- [ ] Client-side sink → `javascript:`/`data:` → escalate to [[xss]].
- [ ] Chain: OAuth `redirect_uri` theft ([[oauth-attacks]]), SSRF allowlist bypass ([[ssrf]]).
- [ ] Confirm navigation from the trusted origin to your host (or the JS escalation).

## See also

[[oauth-attacks]] · [[ssrf]] · [[xss]] · [[csrf]] · [[oswa-exam]]

*Sources: [[payloadsallthethings]] (redirect bypass strings, shared with the OAuth `redirect_uri` catalogue); [[colleague-web-wiki]] (WSTG-CLNT-04, ASVS V3.7.2 remediation).*
