---
type: tool
title: Burp Suite
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Burp Suite

The core web-testing platform: an intercepting proxy plus tools for manual tampering,
fuzzing, and analysis. It sits between browser and server so every request/response is
inspectable and modifiable — the backbone of the [[web-app-assessment]] workflow.

## Setup

- Use Burp's **built-in browser** (proxy + CA cert pre-wired) or point a browser at
  `127.0.0.1:8080` and install the Burp CA cert for HTTPS.
- Set **Target → Scope** to the in-scope host(s) and enable "show only in-scope" so history
  and scans stay clean.

## Tools you actually use

- **Proxy → HTTP history** — the record of everything. Turn *Intercept* off for browsing,
  on when you need to catch/modify a specific request. Right-click → *Send to…*.
- **Repeater** — the workhorse: resend and hand-edit a single request, watch the response.
  This is where you confirm [[sql-injection]] contexts, [[ssti]] fingerprints, [[xxe]]
  payloads, [[idor]] reference swaps, [[command-injection]] separators.
- **Intruder** — automate a request with payload sets: *Sniper* (one position), *Cluster
  bomb* (multi-position combos). Fuzz parameters, brute IDs for [[idor]], run
  [[directory-traversal]] wordlists. (Community edition throttles it.)
- **Decoder** — encode/decode and URL-decode nested bodies; used to read a DataTables POST
  when finding the [[sql-injection]] sink.
- **Comparer** — diff two responses (great for boolean-blind SQLi / auth differences).
- **Sequencer** — assess token randomness (session/CSRF token entropy).

## Professional features

- **Scanner** — passive + active vulnerability scanning (not in Community).
- **Collaborator** — external interaction server for **out-of-band** detection: blind
  [[ssrf]], blind [[xxe]], blind [[command-injection]], and OOB [[sql-injection]].
- **BApp extensions** for extra capabilities.

## Limits / gaps

Community edition lacks Scanner/Collaborator and throttles Intruder. Burp automates
interaction, not judgement — it won't find context-specific bugs (e.g. the `ORDER BY`
[[sql-injection]]) that need manual insight. Pair with [[sqlmap]] for heavy SQLi dumping.

*Source: [[web-200-oswa]] module 4 (Introduction to Burp Suite).*
