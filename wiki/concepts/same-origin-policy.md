---
type: concept
title: Same-Origin Policy (SOP)
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Same-Origin Policy (SOP)

The browser's baseline isolation rule: script from one **origin** can't read data from
another. An *origin* is the tuple **scheme + host + port** — `https://app.com` differs from
`http://app.com` (scheme), `https://api.app.com` (host) and `https://app.com:8443` (port).

## What SOP does and doesn't stop

- **Stops:** JS on origin A from *reading* responses, DOM, cookies or storage of origin B.
- **Does not stop:** the browser from *sending* a request to origin B with B's cookies
  attached. That asymmetry is exactly why [[csrf]] exists — the request goes through and is
  authenticated; SOP only blocks *reading the response*.

## Relationships

- **[[cors-misconfiguration|CORS]]** is the sanctioned way to *relax* SOP for reads; misconfigure
  it and cross-origin reads become possible.
- **[[samesite-cookies|SameSite]]** cookies restrict the *sending* side that SOP leaves open,
  directly mitigating CSRF.
- **[[xss]]** executes *inside* an origin, so it isn't constrained by SOP at all — it acts
  as the origin.

Note the related but distinct notion of **site** (registrable domain + scheme, per the
public-suffix list) used by SameSite: `a.app.com` and `b.app.com` are different *origins*
but the same *site*.

*Source: [[web-200-oswa]] module 7.*
