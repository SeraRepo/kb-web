---
type: tool
title: CeWL
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# CeWL

Custom Word List generator: crawls a target site and harvests the words it contains,
producing an app-specific wordlist. Domain vocabulary (product names, jargon) makes far
better content-discovery and password lists than generic wordlists.

## Install

Preinstalled on Kali (`cewl`).

## Cheat-sheet

```bash
cewl -d 2 -m 5 -w words.txt https://T                 # crawl depth 2, min word length 5
cewl -d 2 -m 5 --lowercase -w words.txt https://T     # normalise case
cewl -d 2 -m 5 --with-numbers -w words.txt https://T  # keep words containing digits
cewl -e --email_file emails.txt https://T             # also scrape email addresses (usernames)
```

Post-process for password policies (append years/symbols) with `hashcat --stdout` rules or
`john --rules`, then feed to [[hydra]] or [[ffuf]].

## Mapping & limits

Produces the **custom wordlists** step of [[web-app-assessment]] enumeration; feeds
[[ffuf]]/[[gobuster]] (content discovery) and [[hydra]] (credential brute). Only sees
crawlable content (respect scope/robots); combine with SecLists for coverage.

*Source: [[web-200-oswa]] module 3.3 (sourcing / creating wordlists).*
