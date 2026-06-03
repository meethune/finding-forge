---
title: "Web — Missing Security Headers"
tags:
  - web
finding_type: Web
severity:
  rating: Low
---

## Description

HTTP responses lack recommended security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Aligns with OWASP A02:2025.

## Impact

Increased XSS, clickjacking, and downgrade attack surface; not always directly exploitable alone.

## Mitigation

Deploy baseline header set; use CSP with nonces/hashes; enable HSTS with includeSubDomains where appropriate.

## Replication Steps

1. Request key application pages.
2. Enumerate response headers.
3. Compare to organizational baseline.
4. Document missing headers per route.
5. Recommend configuration.

## References

- https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Guidance

Often bundled under A02 or reported as Low hardening.
