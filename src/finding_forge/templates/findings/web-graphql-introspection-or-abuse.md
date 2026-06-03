---
title: "Web — GraphQL Introspection or Abuse"
tags:
  - web
finding_type: Web
severity:
  rating: Medium
---

## Description

GraphQL endpoint exposes schema via introspection or lacks query depth/complexity limits enabling data harvesting or DoS.

## Impact

Expanded attack surface, bulk data extraction, and service degradation.

## Mitigation

Disable introspection in production; query cost analysis; rate limits; field-level authorization.

## Replication Steps

1. Send introspection query.
2. Map sensitive types and mutations.
3. Test batching and deep queries.
4. Attempt unauthorized object access.
5. Document schema exposure and limits.

## References

- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

## Guidance

API-specific; adjust severity for sensitive schema exposure.
