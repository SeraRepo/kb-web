---
type: technique
title: Cross-Site Request Forgery (CSRF)
lang: en
status: active
wstg: ["WSTG-SESS-05"]
owasp_top10: ["A01:2021"]
owasp_api: []
asvs: ["V3.3.2", "V3.5.3"]
cwe: ["CWE-352"]
attack: []
cvss: ""
sources: [web-200-oswa]
updated: 2026-09-17
---

# Cross-Site Request Forgery (CSRF)

**TL;DR** — The browser attaches the victim's cookies to *any* request to a site,
including one triggered from an attacker's page. If a state-changing request carries no
unpredictable token and the session cookie isn't `SameSite`-restricted, an attacker page
can make the victim's browser perform that action while logged in.

> Framework: **A01:2021 – Broken Access Control** (CSRF, `CWE-352`). WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Preconditions

1. Action driven purely by a **cookie-based session** (ambient authority).
2. The request is **predictable** (no per-request secret the attacker can't guess).
3. Cookies are sent cross-site — i.e. **not** `SameSite=Lax/Strict` for this flow
   ([[samesite-cookies]]).

Remove any one and classic CSRF breaks.

## Detection

- Capture a state-changing request in [[burp-suite|Burp]]. Does it contain an
  unpredictable token (hidden field / header)? **Remove or change it** and replay — if it
  still succeeds, no effective CSRF protection.
- Check the session cookie's `SameSite` attribute (missing / `None` → cross-site sending
  possible).
- Confirm the action works via a simple cross-site replay (new form, no token).

## Exploitation

Host a page that auto-submits the forged request from the victim's browser:

```html
<!-- attacker page: victim's cookies ride along automatically -->
<form action="https://target/webtools/control/createUserLogin" method="POST">
  <input name="USERNAME" value="csrftest">
  <input name="CURRENT_PASSWORD" value="Password123!">
  <input name="..." value="...">        <!-- remaining required fields -->
</form>
<script>document.forms[0].submit()</script>
```

GET-based actions are even simpler (`<img src="https://target/action?x=1">`). JSON APIs are
harder (custom `Content-Type` triggers preflight) unless the endpoint accepts
`text/plain`/form encoding.

### Variants

- **Login CSRF:** force the victim to log in *as the attacker* (their subsequent activity
  then accrues to the attacker's account) — the login form has no token.
- **JSON endpoints:** a cross-site `fetch` with `application/json` triggers a CORS preflight
  that blocks it — but endpoints accepting `text/plain`/form encoding, or not verifying
  `Content-Type`, stay CSRF-able. See [[cors-misconfiguration]].
- **Method/param pollution:** hidden `_method=PUT` overrides or duplicated parameters can slip
  past naive checks.

## Worked example — Apache OFBiz, forge an admin creating a privileged user

From [[web-200-oswa]] (Apache OFBiz, Java). User creation is a POST to
`/webtools/control/createUserLogin` with **no anti-CSRF token**. An attacker page that
auto-submits that form will, when opened by a logged-in admin, create a new account
(`csrftest`) — potentially privileged. The lab makes the `SameSite` dependency explicit:
OFBiz's `JSESSIONID` is set **without** a `SameSite` attribute, so the browser sends it
cross-site and the attack works; forcing the cookie to `Lax`/`Strict` in DevTools stops the
session cookie from riding along and the forged request is no longer authenticated.

## Confirming impact

Show the state change performed without the victim's intent (account created, email/
password changed, funds moved). Impact scales with the action reachable and the victim's
privilege (admin → account takeover / full compromise).

## Remediation

- **Anti-CSRF tokens** ([[csrf-tokens]]): unpredictable, per-session (or per-request),
  validated server-side on every state change.
- **`SameSite=Lax` (or `Strict`)** on session cookies ([[samesite-cookies]]) — kills the
  cross-site cookie send for most flows.
- Re-authentication / step-up for sensitive actions; avoid state change on GET.

Caveat: none of this helps if the site has [[xss]] — script running in-origin forges
requests *with* the token.

## Quick checklist

- [ ] State-changing request (create/change/delete/transfer) driven purely by a cookie session?
- [ ] Anti-CSRF token present? Remove/alter it and replay — still succeeds → no effective protection.
- [ ] Session cookie `SameSite`? missing/`None` → cross-site send works ([[samesite-cookies]]).
- [ ] Build a PoC (auto-submit form; `<img>` for GET). JSON-only → needs `text/plain`/form or a [[cors-misconfiguration|CORS]] gap.
- [ ] Confirm the action fires cross-site as the victim. Remember [[xss]] defeats tokens outright.

## See also

[[xss]] · [[samesite-cookies]] · [[same-origin-policy]] · [[csrf-tokens]] · [[cors-misconfiguration]]

*Source: [[web-200-oswa]] module 7 (Cross-Origin Attacks, OFBiz case study).*
