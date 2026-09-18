---
type: technique
title: Known-vulnerable components (fingerprint → CVE → PoC)
lang: en
status: active
wstg: ["WSTG-INFO-08", "WSTG-INFO-09"]
owasp_top10: ["A06:2021"]
owasp_api: []
asvs: []
cwe: ["CWE-1104"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa]
updated: 2026-09-17
---

# Known-vulnerable components (fingerprint → CVE → PoC)

**TL;DR** — A huge share of real footholds isn't a bug *you* find — it's recognising the exact
product and version, finding its **public CVE / exploit**, and **adapting the PoC**. This
recon-to-exploit workflow is the connective tissue of almost every HTB/PG practice box and of
the [[web-200-oswa|WEB-200]] real-app case studies (Piwigo, OFBiz, Craft, Home Assistant…). Not a
single vuln class — a **methodology** you run on every target.

> Framework: **A06:2021 – Vulnerable and Outdated Components**, `CWE-1104` (unmaintained
> third-party component), ATT&CK `T1190`. Enumeration anchors: WSTG `WSTG-INFO-08/09`
> (fingerprint framework/application).

## The workflow

1. **Fingerprint precisely — product + *version*.** The version is what turns "some CMS" into
   "this exact CVE". Sources below.
2. **Find the vulnerability.** Search the exact product+version for a public advisory/exploit.
3. **Read and *adapt* the PoC** — understand it before running (it's untrusted code); set the
   target/host/params, adjust for the version/config, defang anything weaponised.
4. **Confirm impact** with a benign proof (`id`, a file read, a callback), then the foothold →
   [[reverse-shells|shell]].

## 1. Fingerprint the version

```bash
whatweb -a3 https://T          # tech + versions from headers/tags/scripts
wappalyzer / builtwith         # framework + plugin detection
nmap -sV --script=http-* T     # NSE http-* scripts (allowed on OSWA)
```
Manual tells (often exact versions):

```text
Headers:   Server, X-Powered-By, X-Generator, X-Drupal-Cache, Set-Cookie name (e.g. CRAFT_CSRF)
HTML:      <meta name="generator" content="Joomla! 3.9.4">   comments, template paths
Files:     /CHANGELOG.txt /VERSION /readme.html /composer.json /package.json /package-lock.json
           /wp-includes/version.php  /administrator/manifests/  favicon hash (Shodan http.favicon.hash)
Errors:    stack traces / debug pages leak framework + version
```

### Source & version disclosure (a shortcut to both)

Exposed VCS/backup files hand you the source (→ read the bug) *and* the version:

```bash
# .git exposed? dump and review the source
curl -s https://T/.git/HEAD                         # "ref: refs/heads/..." => .git is served
git-dumper https://T/.git ./src                     # (or GitTools/gitdumper) → full repo
# other leaks to try:
/.git/config  /.svn/entries  /.DS_Store  /.env  /config.php.bak  /index.php~  /#index.php#
```
Content-discovery a backup/old-file wordlist ([[ffuf]] + SecLists `Discovery/Web-Content/…backup`);
`.git` review often reveals both the component version and a committed secret or the vulnerable
sink (HTB *Pilgrimage*).

## 2. Find the CVE / exploit

```bash
searchsploit <product> <version>        # local Exploit-DB copy (always exam-safe)
searchsploit -m <edb-id>                # copy the PoC locally to read/adapt
```
Also: **NVD / cve.org**, the vendor **security advisory** / GitHub **GHSA**, `github.com` search
for `"<product>" RCE PoC`, **Packet Storm**, and the project's CHANGELOG (fixed-in notes reveal
what was vulnerable before). **nuclei** with `-t cves/` templates finds known CVEs fast — it's a
*targeted* template scanner; the OSWA-banned category is **mass** vulnerability scanners
(Nessus/OpenVAS/…), so prefer `searchsploit`/manual lookup and avoid broad mass-scan behaviour
(confirm against the [[oswa-exam|exam guide]]).

## 3. Read, adapt, confirm

Never run a PoC blind — read it, set `RHOST`/URL/params, and swap any weaponised payload for a
benign proof first. Many "exploits" need a small tweak (a path, a token, a version-specific
offset). Reproduce with [[curl]] / [[burp-suite|Burp]] so you understand each request for the
report.

## Recurring examples (practice boxes & real apps)

| Component | CVE / class | Effect |
|---|---|---|
| **dompdf** | CVE-2022-28368 | poisoned `@font-face` CSS → PHP write → **RCE** (HTB *Interface*) |
| **ImageMagick** | CVE-2022-44268 | PNG `profile` chunk names a file → **arbitrary file read** via `identify` (HTB *Pilgrimage*) |
| **pdfkit / wkhtmltopdf** | CVE-2022-25765 | URL param → **command injection** (HTB *Precious*) |
| **Tiny File Manager** | CVE-2021-45010 + default creds | authenticated **upload → webshell** (HTB *Soccer*) |
| **GitPython** | CVE-2022-24439 | `ext::sh -c <cmd>` clone URL → **RCE** (see [[command-injection]] argument injection) |
| **Apache OFBiz / Piwigo / Craft** | per-version | the [[web-200-oswa|WEB-200]] case studies are all "known app → its bug" |

## Confirming impact

Prove the specific CVE fired (the file it reads, the command it runs, the auth it bypasses) — and
in the report, **document the exact product+version and the CVE ID** you matched, plus your
reproduction. Severity follows the CVE (often Critical for RCE).

## Remediation

- **Inventory** every component and version (SBOM); **remove** unused dependencies; **patch/upgrade**
  on a schedule and monitor advisories (GHSA/NVD) — the A06:2021 control set.
- Don't expose version tells or VCS/backup files: block `.git`/`.svn`/`.env`/`*~`/`*.bak` at the
  server; strip `X-Powered-By`/generator tags; generic error pages.

## Pitfalls / notes

- The **version** is everything — a CVE for 4.2.1 may not fire on 4.2.3. Get it exact.
- Prefer reading the source (`.git`/decompiled/`composer.json`) to *confirm* the sink before
  trusting a generic PoC.
- Public PoCs are untrusted code — read before running; never paste an attacker-hosted payload
  blind (this wiki documents, it never runs them against a live host).

## See also

[[web-app-assessment]] · [[directory-traversal]] · [[command-injection]] · [[file-upload]] · [[reverse-shells]] · [[oswa-exam]]

*Sources: [[web-200-oswa]] (real-app case studies exploit known-component bugs); 0xdf HTB gap-analysis + OSWA practice-box research (dompdf/ImageMagick/pdfkit/Tiny File Manager/GitPython, `.git` disclosure).*
