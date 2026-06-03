---
title: "Web — Credential Stuffing and Password Spray Susceptibility"
tags:
  - web
finding_type: Web
severity:
  rating: High
---

## Description

Authentication endpoints lack effective controls against automated login attempts using breached credentials or password variants.

## Impact

Mass account compromise without targeting a single user.

## Mitigation

MFA; rate limiting; CAPTCHA; breached-password checks; anomaly detection; uniform errors.

## Replication Steps

1. Test login rate limits from single IP and distributed simulation.
2. Verify lockout and alerting.
3. Use test accounts only.
4. Document missing controls.
5. Reference A07:2025.

## References

- https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

## Detection

**Network:** High volume 401 on /login; geographic dispersion; known stuffing tool user-agents.

## Guidance

Process/control finding under A07; not a CWE Top 25 entry.
