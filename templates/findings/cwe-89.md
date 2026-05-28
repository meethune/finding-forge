---
title: "CWE-89 — SQL Injection"
cwe_ids:
  - CWE-89
tags:
  - web
  - cwe-89
finding_type: Web
severity:
  rating: High
---

## Description

User input is incorporated into SQL queries without parameterization, allowing attackers to alter query logic. CWE-89 ranked #2 in CWE Top 25:2025.

## Impact

Full database read/write, authentication bypass, and potential OS command execution via database features.

## Mitigation

Parameterized queries; ORMs; least-privilege DB accounts; input validation; WAF as defense in depth; avoid dynamic concatenation.

## Replication Steps

1. Map parameters interacting with the database.
2. Inject boolean, union, time-based, or error-based payloads.
3. Confirm SQL execution via errors, data, or timing.
4. Limit proof to minimal rows.
5. Document vulnerable query context.

## References

- https://cwe.mitre.org/data/definitions/89.html

## Guidance

Parent: A05:2025 — Injection. Critical if privileged DB or xp_cmdshell-equivalent available.
