---
title: "CWE-78 — OS Command Injection"
cwe_ids:
  - CWE-78
tags:
  - web
  - cwe-78
finding_type: Web
severity:
  rating: Critical
---

## Description

User input is passed to OS shell commands without sanitization. CWE-78 ranked #9 with 20 KEV CVEs.

## Impact

Remote command execution with application service account privileges.

## Mitigation

Avoid shell invocation; use parameterized APIs; strict allowlists; least-privilege service accounts.

## Replication Steps

1. Identify parameters passed to ping, nslookup, or system utilities.
2. Inject command separators (; | &&).
3. Confirm execution via time delay or out-of-band callback.
4. Limit to harmless proof.
5. Document command line constructed.

## References

- https://cwe.mitre.org/data/definitions/78.html

## Detection

**Host:** Process creation monitoring for shell children from web services.

## Guidance

Parent: A05:2025 — Injection.
