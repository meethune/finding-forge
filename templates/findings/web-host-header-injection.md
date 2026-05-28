---
title: "Web — Host Header Injection"
tags:
  - web
finding_type: Web
severity:
  rating: Medium
---

## Description

Application trusts Host header for redirects, links, or password reset URLs, enabling cache poisoning or token theft.

## Impact

Password reset poisoning, web cache poisoning, and SSRF in some stacks.

## Mitigation

Validate Host against allowlist; use configured canonical URL; avoid Host in security decisions.

## Replication Steps

1. Modify Host header on sensitive requests.
2. Observe reflected host in links or emails (test mail sink).
3. Test password reset flow.
4. Document injection points.
5. Recommend canonical URL config.

## References

- https://portswigger.net/web-security/host-header

## Guidance

Related to HTTP smuggling and cache attacks.
