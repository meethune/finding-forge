---
title: "CWE-20 — Improper Input Validation"
cwe_ids:
  - CWE-20
tags:
  - web
  - cwe-20
finding_type: Web
severity:
  rating: Medium
---

## Description

The application does not validate input sufficiently before use. CWE-20 dropped six ranks to #18 in 2025 but remains prevalent.

## Impact

Enables injection, logic errors, and instability depending on sink.

## Mitigation

Validate type, length, range, and format server-side; allowlists over denylists; validate at trust boundaries.

## Replication Steps

1. Map trust boundaries and inputs.
2. Submit boundary and malformed values.
3. Correlate with downstream vulnerabilities.
4. Document missing validation.
5. Link to specific exploit if found.

## References

- https://cwe.mitre.org/data/definitions/20.html

## Guidance

Often reported alongside specific injection CWEs.
