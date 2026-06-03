---
title: "Web — Subdomain Takeover"
tags:
  - web
finding_type: Web
severity:
  rating: Medium
---

## Description

Dangling DNS records point to deprovisioned third-party services, allowing attackers to claim the hostname.

## Impact

Phishing, cookie scope attacks, and reputational damage on trusted subdomain.

## Mitigation

Remove stale DNS; monitor CNAMES; claim or delete orphaned resources; periodic subdomain audits.

## Replication Steps

1. Enumerate subdomains.
2. Identify NXDOMAIN or unclaimed SaaS fingerprints.
3. Claim resource in authorized test.
4. Document DNS record.
5. Recommend cleanup.

## References

- https://owasp.org/www-community/attacks/Subdomain_Takeover

## Guidance

Infrastructure/OSINT finding; often pre-engagement.
