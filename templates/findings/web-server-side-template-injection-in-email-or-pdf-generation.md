---
title: "Web — Server-Side Template Injection in Email or PDF Generation"
tags:
  - web
finding_type: Web
severity:
  rating: Critical
---

## Description

Secondary template engines used for reports or emails process user input unsafely (related to CWE-917).

## Impact

RCE on server generating documents or messages.

## Mitigation

Sandbox template engines; no user input in templates; use logicless formats.

## Replication Steps

1. Identify export/email features accepting user fields.
2. Inject template expressions.
3. Confirm execution in lab.
4. Document feature.
5. Recommend safe libraries.

## References

- https://cwe.mitre.org/data/definitions/917.html

## Guidance

Use CWE-917 when confirmed; this row highlights common secondary sinks.
