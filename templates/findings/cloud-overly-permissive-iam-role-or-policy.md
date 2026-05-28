---
title: "Cloud — Overly Permissive IAM Role or Policy"
tags:
  - cloud
finding_type: Cloud
severity:
  rating: High
---

## Description

Cloud identities (users, roles, service accounts) have excessive permissions enabling lateral movement or data access beyond least privilege.

## Impact

Compromise of one principal may lead to organization-wide control plane access.

## Mitigation

Least privilege; permission boundaries; regular access reviews; deny policies; MFA for humans.

## Replication Steps

1. Inventory IAM policies attached to roles in scope.
2. Identify admin-equivalent or wildcard actions.
3. Demonstrate excessive access with read-only proof.
4. Map blast radius.
5. Recommend policy tightening.

## References

- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/

## Guidance

Common in cloud configuration reviews.
