---
title: "Web — CORS Misconfiguration"
tags:
  - web
finding_type: Web
severity:
  rating: High
---

## Description

Cross-Origin Resource Sharing allows untrusted origins to read authenticated API responses, enabling data theft from victim browsers.

## Impact

Sensitive API data exfiltration when victim visits attacker page while authenticated.

## Mitigation

Strict Origin allowlists; avoid Access-Control-Allow-Credentials with wildcard; validate Origin server-side.

## Replication Steps

1. Identify ACAO and ACAC headers on sensitive APIs.
2. Reflect attacker Origin.
3. Demonstrate credentialed cross-origin read in lab.
4. Document affected endpoints.
5. Recommend policy fix.

## References

- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
- https://portswigger.net/web-security/cors

## Guidance

Mapped under A01:2025; also CWE-346 family.
