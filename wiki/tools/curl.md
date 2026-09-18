---
type: tool
title: curl
lang: en
status: active
sources: []
updated: 2026-07-31
---

# curl

Scriptable HTTP client. Once [[burp-suite|Burp]] confirms a finding, curl reproduces and
**automates** it — ideal for iterating payloads, writing PoCs, and putting reproduction
steps in a report.

## Install

Everywhere (`curl`). `-s` silent, `-i` include response headers, `-k` skip TLS verify,
`-v` verbose.

## Cheat-sheet

```bash
curl -sik https://T/                                   # headers + body
curl -sk -X POST -d 'user=a&pass=b' https://T/login    # form POST
curl -sk -H 'Content-Type: application/json' -d '{"id":1}' https://T/api
curl -sk -b 'SESSION=abc; role=user' https://T/account # send cookies
curl -sk -L https://T/x                                # follow redirects

# technique repros:
curl -sk -H 'Origin: https://evil.example' -I https://T/api          # CORS: watch ACAO/ACAC
curl -sk --data-binary @xxe.xml -H 'Content-Type: application/xml' https://T/import  # XXE
curl -sk "https://T/note?noteid=11"                    # IDOR: iterate the reference
curl -sk "https://T/fetch?url=http://127.0.0.1:8080"   # SSRF probe
```

## Mapping & limits

The go-to for reproducing/scripting [[cors-misconfiguration]], [[xxe]], [[idor]], [[ssrf]],
and any request-level finding across [[web-app-assessment]]. It's a raw client — no JS
execution (DOM [[xss]] needs a browser) and no session/state management beyond what you
pass explicitly.

*General reference tool page.*
