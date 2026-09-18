---
type: tool
title: Gobuster
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Gobuster

Brute-forcer for URIs, DNS subdomains, and virtual hosts (Go). Simple and fast; a common
alternative to [[ffuf]] for content discovery in [[web-app-assessment]].

## Install

Preinstalled on Kali (`gobuster`).

## Cheat-sheet

```bash
# directory/file discovery
gobuster dir -u https://T -w /usr/share/seclists/Discovery/Web-Content/common.txt \
             -x php,txt,html -t 50 -k                     # -k: skip TLS verify
gobuster dir -u https://T -w wl.txt -s 200,204,301,302,307,403 -b ""   # status filtering

# DNS subdomain brute
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# virtual-host brute
gobuster vhost -u https://T -w subdomains.txt --append-domain
```

## Mapping & limits

Feeds content/host discovery in [[web-app-assessment]]; the directory results seed
[[directory-traversal]] and other per-endpoint testing. Less flexible than [[ffuf]]/[[wfuzz]]
for arbitrary fuzzing positions (it targets specific modes). Wordlist-bound — see [[cewl]].

*Source: [[web-200-oswa]] module 3 (automated endpoint discovery).*
