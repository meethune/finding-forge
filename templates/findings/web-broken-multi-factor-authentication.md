---
title: "Web — Broken Multi-Factor Authentication"
tags:
  - web
finding_type: Web
severity:
  rating: High
---

## Description

MFA can be bypassed, disabled by design, or uses weak factors (SMS-only without rate limits). OWASP A07:2025.

## Impact

Account takeover despite MFA deployment perception.

## Mitigation

Phishing-resistant MFA (FIDO2/WebAuthn); enforce MFA on all users; protect MFA enrollment; rate limit OTP.

## Replication Steps

1. Map MFA enrollment and recovery flows.
2. Test bypass (cookie replay, race, fallback to password-only).
3. Assess OTP brute force.
4. Document bypass.
5. Recommend stronger factors.

## References

- https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

## Guidance

Use when MFA is present but ineffective; parent A07:2025.
