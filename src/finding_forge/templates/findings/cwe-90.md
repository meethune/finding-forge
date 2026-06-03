---
title: "CWE-90 — LDAP Injection"
cwe_ids:
  - CWE-90
tags:
  - web
  - cwe-90
finding_type: Web
severity:
  rating: High
---

## Description

Untrusted input in LDAP queries without escaping. Mapped under A05:2025.

## Impact

Authentication bypass and directory data extraction.

## Mitigation

Parameterized LDAP APIs; escape special characters; least-privilege LDAP bind.

## Replication Steps

1. Identify LDAP-backed login or search.
2. Inject LDAP metacharacters (*)(|)(&).
3. Observe authentication or data changes.
4. Document parameter.
5. Recommend parameterized queries.

## References

- https://cwe.mitre.org/data/definitions/90.html

## Guidance

Parent A05:2025.
