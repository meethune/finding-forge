---
title: "Web — JWT Validation Weakness"
tags:
  - web
finding_type: Web
severity:
  rating: High
---

## Description

JSON Web Tokens accepted with weak or missing signature verification, algorithm confusion, or excessive lifetime.

## Impact

Authentication bypass and privilege escalation via forged tokens.

## Mitigation

Validate alg and signature; reject none; short lifetimes; refresh token rotation; secure key storage.

## Replication Steps

1. Capture JWT from application.
2. Test alg=none, key confusion, and expired token acceptance.
3. Modify claims (role, sub).
4. Access protected resources.
5. Document validation flaws.

## References

- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

## Guidance

Parent A07:2025. Use when JWT is the auth mechanism.
