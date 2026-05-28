---
title: "CWE-74 — Injection (Generic / NoSQL)"
cwe_ids:
  - CWE-74
tags:
  - web
  - cwe-74
finding_type: Web
severity:
  rating: High
---

## Description

Injection into NoSQL or other interpreters when user input alters query structure (MongoDB operators, etc.). Related to A05:2025.

## Impact

Authentication bypass and unauthorized data access in document databases.

## Mitigation

Use typed APIs; validate input types; avoid string-built queries; least privilege.

## Replication Steps

1. Identify JSON/NoSQL endpoints.
2. Inject operator objects ($gt, $ne, etc.).
3. Observe auth bypass or data leak.
4. Document payload.
5. Recommend safe query APIs.

## References

- https://cwe.mitre.org/data/definitions/74.html

## Guidance

Use when SQLi template does not apply.
