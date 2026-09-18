---
type: tool
title: Wfuzz
lang: en
status: active
sources: []
updated: 2026-07-31
---

# Wfuzz

Flexible web fuzzer (Python). Largely superseded by [[ffuf]] for speed, but still handy for
multi-position fuzzing and fine-grained response filtering. `FUZZ`/`FUZ2Z` mark injection
points.

## Install

Preinstalled on Kali (`wfuzz`); else `pipx install wfuzz`.

## Cheat-sheet

```bash
# content discovery, hide 404s
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 https://T/FUZZ

# credential fuzzing, hide responses containing "invalid"
wfuzz -c -z file,rockyou.txt -d "user=admin&pass=FUZZ" --hs "invalid" https://T/login

# two positions: user x pass
wfuzz -c -z file,users.txt -z file,pass.txt -d "user=FUZZ&pass=FUZ2Z" --hc 401 https://T/login

# IDOR / numeric enumeration, hide by line count
wfuzz -c -z range,1-1000 --hl 5 "https://T/user?id=FUZZ"
```

Filters mirror [[ffuf]]: `--hc/--sc` (codes), `--hl/--sl` (lines), `--hw/--sw` (words),
`--hh/--sh` (chars).

## Mapping & limits

Same roles as [[ffuf]]/[[gobuster]] in [[web-app-assessment]] — content discovery,
[[idor]] enumeration, auth fuzzing. Slower than ffuf; reach for it when you need its
multi-payload/iterator modes.

*General reference tool page.*
