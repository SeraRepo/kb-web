---
type: tool
title: ffuf
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# ffuf

Fast web fuzzer (Go). The `FUZZ` keyword marks where each wordlist entry is substituted —
so it does content discovery, parameter discovery, vhost brute-forcing, [[idor]] ID
enumeration, and auth fuzzing from one tool.

## Install

Preinstalled on Kali (`ffuf`); else `go install github.com/ffuf/ffuf/v2@latest`.

## Cheat-sheet

```bash
# directory / file discovery
ffuf -u https://T/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -u https://T/FUZZ -w wl.txt -e .php,.txt,.bak -mc 200,301,403   # extensions, match codes

# virtual-host discovery (filter by response size once you know the baseline)
ffuf -u https://T/ -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234

# parameter-name discovery
ffuf -u "https://T/page?FUZZ=1" -w params.txt -fw 42                 # filter by word count

# IDOR / object-id enumeration
ffuf -u "https://T/user?id=FUZZ" -w <(seq 1 5000) -mc 200 -fr "not found"

# login / auth fuzzing
ffuf -u https://T/login -X POST -d "user=admin&pass=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" -w rockyou.txt -fc 401
```

**Filters/matchers** are the skill: `-mc` (match codes), `-fc` (filter codes), `-fs`
(size), `-fw` (words), `-fl` (lines), `-fr` (regex). Start broad, then filter out the
baseline noise.

## Mapping & limits

Core of content discovery in [[web-app-assessment]]; drives path fuzzing for
[[directory-traversal]] and ID enumeration for [[idor]]. Only as good as the wordlist —
pair with [[cewl]]/SecLists. Alternatives: [[gobuster]], [[wfuzz]], feroxbuster.

*Source: [[web-200-oswa]] module 3 (automated endpoint discovery).*
