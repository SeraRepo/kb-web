---
type: tool
title: Hydra
lang: en
status: active
sources: []
updated: 2026-07-31
---

# Hydra

Parallelised network login brute-forcer. For web work it targets HTTP forms and HTTP basic
auth; it also covers SSH/FTP/etc. for pivoting. Pair with [[cewl]]-built wordlists.

## Install

Preinstalled on Kali (`hydra`).

## Cheat-sheet

The web module needs `path:body:failure-marker`. `^USER^`/`^PASS^` are the injection points;
`F=` marks a **failure** string (or `S=` a success string):

```bash
# POST login form
hydra -L users.txt -P rockyou.txt T http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# same but success-based, and keep a cookie the app sets on the login page
hydra -l admin -P pass.txt T http-post-form \
      "/login:user=^USER^&pass=^PASS^:S=302:H=Cookie: PHPSESSID=abc"

# HTTP basic auth
hydra -l admin -P pass.txt -f T http-get /admin

# combined user:pass list; -f stop on first hit; -t threads
hydra -C combos.txt -f -t 16 ssh://T
```

## Mapping & limits

Drives the credential-attack part of [[web-app-assessment]]; wordlists come from
[[cewl]]/SecLists. **Limits:** account lockout and rate limiting will burn accounts and
noise you up; per-request **CSRF tokens** break naive form brute (the token changes each
request — script it with [[curl]]/[[ffuf]] grabbing the fresh token, or use Burp Intruder
with a recursive grep). Prefer targeted guesses over full brute in exams.

*General reference tool page.*
