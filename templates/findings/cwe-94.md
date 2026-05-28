---
title: "CWE-94 — Code Injection"
cwe_ids:
  - CWE-94
tags:
  - web
  - cwe-94
finding_type: Web
severity:
  rating: Critical
---

## Description

User input is evaluated as code (eval, dynamic compilation). CWE-94 ranked #10.

## Impact

Arbitrary code execution in application runtime context.

## Mitigation

Never evaluate user input; sandbox if unavoidable; static analysis for dangerous APIs.

## Replication Steps

1. Locate dynamic evaluation sinks.
2. Inject language-specific payloads.
3. Confirm code execution.
4. Document sink location and input vector.
5. Recommend removal of eval patterns.

## References

- https://cwe.mitre.org/data/definitions/94.html

## Guidance

Includes template injection when code is generated—see CWE-917.
