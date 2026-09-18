---
type: tool
title: Netcat (nc)
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Netcat (nc)

The TCP "swiss army knife". In web exploitation its main jobs are **catching reverse
shells** and manual banner-grabbing/protocol poking.

## Install

Preinstalled on Kali (`nc`). Variants differ (`nc` traditional vs `ncat` from Nmap).

## Cheat-sheet

```bash
nc -lvnp 4444                 # listener: catch a reverse shell (see command-injection)
nc TARGET 80                  # manual connection / banner grab
printf 'GET / HTTP/1.0\r\n\r\n' | nc TARGET 80    # raw HTTP request
nc -lvnp 443 > loot.bin       # receive a file over the wire
ncat --ssl -lvnp 4444         # TLS listener (ncat)
```

After catching a shell, stabilise the TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'    # then: Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

## Mapping & limits

The receiving end for a [[command-injection]] (or [[ssti]]) reverse shell; also quick
service banner checks during [[web-app-assessment]] enumeration. Plaintext and single-
connection by default; use `ncat --ssl` / socat for encrypted or robust handlers.

*Source: [[web-200-oswa]] module 13 (obtaining a shell).*
