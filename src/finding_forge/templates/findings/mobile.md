---
title: "Mobile — Insecure Local Data Storage"
tags:
  - mobile
finding_type: Mobile
severity:
  rating: High
---

## Description

Mobile application stores sensitive data (tokens, PII) in cleartext local storage, backups, or logs accessible on rooted/jailbroken devices.

## Impact

Device compromise or backup extraction leads to account takeover.

## Mitigation

Use platform secure storage (Keychain/Keystore); encrypt at rest; exclude sensitive data from logs and backups.

## Replication Steps

1. Analyze mobile app package (static analysis).
2. Inspect local databases and preferences on test device.
3. Review backup and logging behavior.
4. Document stored secrets.
5. Recommend secure APIs.

## References

- https://owasp.org/www-project-mobile-top-10/

## Guidance

Mobile application assessments.
