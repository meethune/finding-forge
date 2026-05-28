---
title: "CWE-79 — Cross-site Scripting (XSS)"
cwe_ids:
  - CWE-79
tags:
  - web
  - cwe-79
finding_type: Web
severity:
  rating: Medium
---

## Description

The application does not neutralize user-controlled input before inclusion in HTML output, allowing scripts to execute in victims' browsers (reflected, stored, or DOM-based). CWE-79 ranked #1 in CWE Top 25:2025.

## Impact

Session hijacking, credential theft, defacement, and chained attacks against authenticated users.

## Mitigation

Context-aware output encoding; CSP; HttpOnly cookies; input validation; framework auto-escaping; sanitize HTML when required using vetted libraries.

## Replication Steps

1. Identify reflection/storage points in HTML, JavaScript, and attribute contexts.
2. Inject canonical XSS probes per context.
3. Confirm execution in victim browser context.
4. Assess scope (stored vs reflected).
5. Capture proof without harming users.

## References

- https://cwe.mitre.org/data/definitions/79.html
- https://owasp.org/Top10/2025/A05_2025-Injection/

## Guidance

Use when XSS is confirmed. Parent: A05:2025 — Injection. Adjust severity for stored/admin impact.
