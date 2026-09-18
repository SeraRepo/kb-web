---
type: tool
title: Nmap
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Nmap

Network/port scanner — the first step of [[web-app-assessment]] enumeration: find live
hosts, open ports, and the services/versions behind them, then hand HTTP ports to the
web-specific tools.

## Install

Preinstalled on Kali (`nmap`). Run privileged for SYN/OS scans (`sudo`).

## Cheat-sheet

```bash
nmap -sn 10.10.10.0/24                         # host discovery (no port scan)
nmap -p- --min-rate 5000 -T4 TARGET            # all 65535 TCP ports, fast
nmap -sV -sC -p 80,443,8080,8443 TARGET        # service/version + default NSE scripts
nmap -sU --top-ports 50 TARGET                 # top UDP ports
```

Web-relevant NSE scripts:

```bash
nmap -p80,443 --script http-enum,http-title,http-headers,http-methods TARGET
nmap -p443 --script ssl-enum-ciphers TARGET     # TLS config
nmap -p80,443 --script http-wordpress-enum TARGET
nmap --script vuln -p 80,443 TARGET             # known-CVE checks (noisy)
```

## Mapping & limits

Feeds the **recon/enumeration** phase of [[web-app-assessment]]; confirms which ports run
HTTP(S) before content discovery. Nmap finds *services*, not web *content* — for paths and
parameters use [[ffuf]] / [[gobuster]]. Version scans and `--script vuln` are noisy; scope
accordingly.

*Source: [[web-200-oswa]] module 3 (enumeration).*
