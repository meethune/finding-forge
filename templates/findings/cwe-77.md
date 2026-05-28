---
title: "CWE-77 — Command Injection"
cwe_ids:
  - CWE-77
tags:
  - web
  - cwe-77
finding_type: Web
severity:
  rating: Critical
---

## Description

Improper neutralization in command interpreters. Ranked #23 in CWE Top 25:2025 (overlaps CWE-78).

## Impact

OS command execution.

## Mitigation

Avoid shells; parameterized APIs; allowlists.

## Replication Steps

1. Find command invocation sinks.
2. Inject metacharacters.
3. Confirm execution safely.
4. Document vector.
5. Recommend fix.

## References

- https://cwe.mitre.org/data/definitions/77.html

## Guidance

Prefer CWE-78 row when OS command specific; keep for CWE alignment.
