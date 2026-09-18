---
type: concept
title: Templating engines
lang: en
status: active
sources: [web-200-oswa]
updated: 2026-07-31
---

# Templating engines

A templating engine renders a **template** (presentation) against a **context** (data),
keeping logic out of markup. A template mixes three things: **static content**,
**expressions** (`{{ user.name }}`) that interpolate values, and **statements**
(`{% if admin %}…{% endif %}`) that control flow.

## The distinction that causes [[ssti]]

- **Safe:** user input is a *context variable* — `render("hi {{name}}", name=input)`. The
  engine treats `input` as data.
- **Unsafe:** user input is concatenated into the *template source* —
  `render("hi " + input)`. Now the engine parses `input` as template code, so
  `{{7*7}}` (or `${…}`, `#{…}`) is evaluated → [[ssti]] → often RCE.

## Common engines by language

| Language | Engines | Expression delimiter |
|---|---|---|
| PHP | Twig, Smarty, Blade | `{{ }}` |
| Python | Jinja2, Mako, Tornado | `{{ }}` |
| Java | Freemarker, Velocity | `${ }` / `#{ }` |
| Node.js | Pug, Handlebars, EJS, Mustache | `#{ }`, `{{ }}`, `<%= %>` |

Knowing the language narrows the engine, and the delimiter that evaluates confirms it —
the basis of the SSTI fingerprinting step.

*Source: [[web-200-oswa]] module 12.*
