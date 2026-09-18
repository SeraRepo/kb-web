---
type: concept
title: SameSite cookies
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# SameSite cookies

`SameSite` controls whether a cookie is sent on **cross-site** requests — the lever that
directly blunts [[csrf]].

- **`Strict`** — never sent on cross-site requests (even top-level navigation). Strongest;
  can break "click a link and be logged in" flows.
- **`Lax`** — sent on top-level **GET** navigations (following a link) but not on cross-site
  POST/subresource/iframe requests. Good default: blocks classic form-POST CSRF.
- **`None`** — always sent; **must** be paired with `Secure`. Required for legitimate
  cross-site cookies (third-party embeds, some SSO).

## Why it matters here

Modern browsers default missing-`SameSite` cookies to **Lax**, but behaviour and grace
periods vary, and a cookie explicitly set `SameSite=None` (or an app relying on old
behaviour) is CSRF-exposed. In the [[csrf]] worked example, OFBiz's `JSESSIONID` is set with
**no** `SameSite` attribute; the exploit depends on the browser sending it cross-site, and
forcing it to `Lax`/`Strict` stops the forged request from being authenticated.

SameSite complements — does not replace — [[csrf-tokens]]: use both. It also does nothing
against [[xss]] (same-origin) or against subdomains sharing a site.

*Source: [[web-200-oswa]] module 7.*
