---
type: methodology
title: OSWA box attack playbook
lang: en
status: active
wstg: []
sources: [web-200-oswa]
updated: 2026-09-17
---

# OSWA box attack playbook

The step-by-step, check-as-you-go roadmap for a single OSWA-type web target: from "the box just
spun up" to **`local.txt` + `proof.txt` captured and documented**. Every step links the technique
or tool page that carries the details. Higher-level context: [[oswa-exam]] (format & rules) and
[[web-app-assessment]] (baseline); coverage tracker: [[wstg-checklist]].

> **Three rules that pass the exam** (from every review): **(1) enumeration is the game** — most
> "stuck" moments are a missed endpoint/param, not a missing exploit; when blocked, go back to
> recon. **(2) Report as you go** — screenshot every step and paste it into the report *while
> exploiting*, never at the end. **(3) No privilege escalation** — OSWA scores the web vuln + flag;
> stop once you have the shell/flag. Time-box ~3 h/target and **rotate** when stuck.
>
> **Tools:** sqlmap/Tplmap/Nikto/Burp/msfvenom/ysoserial are **allowed** (sqlmap is noisy —
> confirm by hand first); **banned:** auto-exploit frameworks, mass scanners, AI/LLMs. Manual is
> the intended path.

---

## Phase 0 — Setup & recon *(first ~15 min; kick off on ALL targets in parallel)*

- [ ] Note the IP, add the hostname: `echo "10.10.10.x target.oswa" | sudo tee -a /etc/hosts`
- [ ] Start a notes file + screenshot folder per target; proxy the browser through [[burp-suite|Burp]] (set **Target → Scope**).
- [ ] **Port/service scan** with [[nmap]]:
  ```bash
  nmap -p- --min-rate 5000 -T4 -oA nmap/all target        # all ports fast
  nmap -sVC -p<open-ports> -oA nmap/svc target            # versions + default scripts
  ```
- [ ] For each HTTP(S) service: **fingerprint the stack** (→ [[known-vulnerable-components]]):
  ```bash
  whatweb -a3 http://target        # server, framework, CMS + versions
  curl -sI http://target           # headers: Server / X-Powered-By / Set-Cookie name
  ```
- [ ] **Kick off content discovery** in the background (leave it running):
  ```bash
  feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -x php,txt,html,bak,zip,old -C 404        # or ffuf/gobuster ([[ffuf]] / [[gobuster]] / [[wfuzz]])
  nikto -h http://target                        # known-issue sweep ([[nikto]])
  ```

## Phase 1 — Enumerate the app *(the make-or-break phase)*

- [ ] **Walk the app by hand** through [[burp-suite|Burp]]: click every link, submit every form; watch the proxy history. Note **every page, parameter, form field, cookie, and header**.
- [ ] Review **content-discovery** hits: `/admin`, `/api`, `/backup`, `robots.txt`, `sitemap.xml`, `.env`, `/.git/`, old/`.bak` files.
- [ ] **Source & version disclosure** (→ [[known-vulnerable-components]]): `curl -s http://target/.git/HEAD` → if served, `git-dumper http://target/.git ./src`. Read JS bundles for endpoints/secrets.
- [ ] **Known-CVE check** on any identified product+version: `searchsploit <product> <version>` (a version match is often the whole box).
- [ ] **Vhosts/subdomains** if a domain is in play: `ffuf -w subdomains.txt -H "Host: FUZZ.target" -u http://target -fs <baseline-size>`.
- [ ] **Wordlists from the app** for later brute/discovery: `cewl http://target -w custom.txt` ([[cewl]]).
- [ ] **Authentication:** register/login; get **two accounts** (low + normal) if you can — you need them for access-control bugs. Note the session mechanism: cookie? `eyJ…` **JWT**? serialized blob?
- [ ] **Deliverable of this phase:** a written map — every **endpoint + input sink + the tech-stack guess** (the guess drives every payload: [[ssti]] engine, [[sql-injection]] DBMS, [[command-injection]] OS).

## Phase 2 — Per-input triage *(the core loop — for EVERY input, ask what it feeds)*

Test query params, POST bodies, JSON fields, path segments, headers (`User-Agent`, `Referer`,
`X-Forwarded-For`, `Host`), and cookies. First-probe = the fastest confirm.

| The input looks like… | First probe | Test for → page | Tool |
|---|---|---|---|
| reflected/stored in the page | canary `zqxjcanary` → find it in source | [[xss]] | Burp |
| reaches a DB query (id/search/sort) | append `'` → error/500/changed page | [[sql-injection]] · [[sql-enumeration]] | [[sqlmap]] (confirm by hand) |
| JSON login / Mongo backend | `{"user":"admin","pass":{"$ne":"x"}}` | [[nosql-injection]] | Burp |
| a filename / path | `?file=../../../../etc/passwd` | [[directory-traversal]] → [[lfi]] | [[ffuf]] |
| a URL the server fetches | `?url=http://<your-listener>/` → watch listener | [[ssrf]] | Burp Collaborator / `nc` |
| passed to an OS command | `;id` · `%0aid` · `$(id)` · `\`id\`` | [[command-injection]] | [[curl]] |
| rendered by a template | polyglot `${{<%[%'"}}%\` then `{{7*7}}` | [[ssti]] | Tplmap (confirm by hand) |
| XML parsed server-side | `Content-Type: application/xml` + entity echo | [[xxe]] | Burp |
| an object reference (`id`,`uid`,`file`) | swap/iterate the value across two accounts | [[idor]] | [[ffuf]] |
| a file upload | `shell.php` → try ext/magic-byte bypasses | [[file-upload]] | Burp |
| login / reset / lockout | default creds, then brute; token flaws | [[authentication-attacks]] | [[hydra]] / [[ffuf]] |
| a token `eyJ…` | decode; tamper a claim; `alg:none` | [[jwt-attacks]] | jwt_tool |
| a redirect param (`next`,`url`) | `?next=//evil.com` | [[open-redirect]] | Burp |
| a base64/serialized blob / `__VIEWSTATE` | tamper a byte → still parses? | [[deserialization]] | ysoserial(.net)/phpggc |
| a cross-origin data read | `Origin: https://evil` → reflected in ACAO? | [[cors-misconfiguration]] | Burp |
| a state-change on cookie auth | token present? `SameSite`? | [[csrf]] | Burp |
| a recognizable product + version | `searchsploit <product> <version>` | [[known-vulnerable-components]] | searchsploit |

> **Manual-first:** confirm each finding by hand (understand *why* it works — the exam and the
> report both reward it) before reaching for sqlmap/Tplmap.

## Phase 3 — Exploit → foothold → flags

- [ ] **Confirm** the vuln with a benign proof (`id`, `document.domain`, a file read, DB `version()`).
- [ ] **Escalate** to the goal: RCE, auth bypass, or data read. Chain where it helps
  ([[xxe]]→[[ssrf]], [[sql-injection]]→file-write webshell, [[ssti]]/[[command-injection]]→shell,
  [[lfi]]→log-poison/`php_filter_chain`→RCE, [[idor]]→mass data).
- [ ] **Get a shell** and upgrade the TTY → [[reverse-shells]]; catch with [[netcat]] (or socat/pwncat for a stable PTY).
- [ ] **Capture the flags:** `local.txt` is reached **through the app** (often an admin/dashboard area); `proof.txt` is on the **filesystem** (`/`, `C:\`, or the user's home). **No privilege escalation is required** — if you have a shell, you have `proof.txt`.

## Phase 4 — Document *(do it continuously, not at the end)*

- [ ] Per finding: full **reproduction** (request/response), a **screenshot per step**, **impact + CVSS**, and **remediation** mapped to the ASVS requirement on the technique page.
- [ ] Record the exact product+version + **CVE ID** when you used one. File any reusable trick back into the wiki as a worked example.

---

## "When I'm stuck" checklist *(work down this list before assuming there's no bug)*

- [ ] **Re-enumerate.** Bigger wordlist; other extensions; recurse into found dirs; vhosts; `robots.txt`/sitemap; JS files for hidden endpoints/params.
- [ ] **Untested inputs.** Every header (`Host`, `X-Forwarded-For`, `User-Agent`, `Referer`, `Cookie`), JSON fields, nested/URL-encoded body params (DataTables `columns[]`), the `Content-Type` itself (flip JSON↔XML↔form).
- [ ] **Other HTTP verbs.** `OPTIONS`/`PUT`/`DELETE`/`PATCH`; `X-HTTP-Method-Override`.
- [ ] **Filters/WAF bypass.** Encoding (URL/double-URL/unicode/`....//`), case, comments, no-space/no-paren — every technique page has a bypass library.
- [ ] **Second-order.** A value stored on one request that lands in a sink on a *later* one (stored XSS, second-order SQLi, log/session poisoning for [[lfi]]).
- [ ] **The stack guess.** Reread errors (they leak DBMS/engine/language); pick the matching payload set; re-check the exact **version → CVE** ([[known-vulnerable-components]]).
- [ ] **Authn context.** Log in / use the *second* account / an admin-reaching stored payload — many sinks only appear post-auth.
- [ ] **Rotate.** Note state, switch targets, come back with fresh eyes. Enumeration you started earlier has finished by now.

## Quick command reference

```bash
# recon
nmap -p- --min-rate 5000 -T4 target ; nmap -sVC -p<ports> target
whatweb -a3 http://target ; curl -sI http://target
# discovery
feroxbuster -u http://target -x php,txt,html,bak -C 404
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://target/FUZZ
ffuf -w subs.txt -H "Host: FUZZ.target" -u http://target -fs 0        # vhosts
# source / version
curl -s http://target/.git/HEAD ; git-dumper http://target/.git ./src
searchsploit <product> <version>
# creds
cewl http://target -w words.txt
hydra -L users.txt -P rockyou.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# listener
nc -lvnp 443     # or: socat -d -d TCP-LISTEN:443,reuseaddr FILE:`tty`,raw,echo=0
```

## See also

[[oswa-exam]] · [[web-app-assessment]] · [[wstg-checklist]] · [[known-vulnerable-components]] · [[reverse-shells]] · [[burp-suite]]

*Source: [[web-200-oswa]] (assessment methodology + challenge machines) synthesised with the OSWA exam-review & HTB/PG box research (2026-09-17).*
