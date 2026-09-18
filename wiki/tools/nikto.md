---
type: tool
title: Nikto
lang: en
status: active
sources: []
updated: 2026-07-31
---

# Nikto

Web server scanner: quick, signature-based sweep for known dangerous files, outdated
software, misconfigurations, and missing security headers. A fast first look during
[[web-app-assessment]] enumeration — not a deep or stealthy tool.

## Install

Preinstalled on Kali (`nikto`).

## Cheat-sheet

```bash
nikto -h https://T                          # basic scan
nikto -h https://T -ssl -port 443
nikto -h https://T -Tuning 1234567890abc    # select test classes (e.g. 9=SQLi, x=reverse)
nikto -h https://T -o report.html -Format htm
nikto -h https://T -useproxy http://127.0.0.1:8080   # route through Burp
```

## Mapping & limits

Surfaces low-hanging misconfig / known-issue leads to feed [[web-app-assessment]]. **Very
noisy** and signature-based → false positives and easily blocked/logged; it does not
understand application logic, so it never replaces manual testing with [[burp-suite|Burp]].
Confirm every hit by hand.

*General reference tool page.*
