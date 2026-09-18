---
type: mitigation
title: Parameterised queries (prepared statements)
lang: en
status: active
owasp_top10: ["A03:2021"]
cwe: ["CWE-89"]
asvs: ["V1.2.4"]
sources: [web-200-oswa]
updated: 2026-07-31
---

# Parameterised queries (prepared statements)

The primary defence against [[sql-injection]]: send the query **structure** and the
**data** to the database separately, so user input is always bound as a value and can never
be parsed as SQL — regardless of what characters it contains.

```php
// PHP (PDO)
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$stmt->execute([$name]);
```
```java
// Java (JDBC)
PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
```
```python
# Python (DB-API) — pass params, never format the string
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
```

Note what is **not** solved by binding: **identifiers** — table/column names and
`ORDER BY`/sort direction — cannot be parameterised (they're structure, not data). That is
exactly the gap exploited in the Piwigo worked example on [[sql-injection]]. For those,
map user input to a **server-side allowlist** of permitted values:

```python
SORT = {"name": "name", "date": "created_at"}          # allowlist
col = SORT.get(user_choice, "name")                    # never interpolate raw input
direction = "ASC" if user_dir == "asc" else "DESC"
```

## Supporting controls (defence in depth)

- **ORM / query builders** help but aren't automatic immunity — raw-SQL escape hatches and
  string-built fragments reintroduce the bug.
- **Least-privilege DB account** (no `FILE`, no DBA) limits blast radius (file read/write,
  RCE).
- Input validation and generic error pages reduce signal to an attacker (kills error-based
  leaks) but are **not** a substitute for binding.

*ASVS `V1.2.4` (parameterised queries / ORMs). ASVS 5.0 also flags that identifiers and `ORDER BY` names can't be escaped — hence the allowlist.
Source: [[web-200-oswa]] modules 8–9.*
