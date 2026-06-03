---
title: "Network — Exposed Management Services"
tags:
  - network
finding_type: Network
severity:
  rating: High
---

## Description

Administrative services (RDP, SSH, WinRM, database admin ports) exposed to untrusted networks without adequate controls.

## Impact

Brute force, credential stuffing, and exploitation of management interfaces.

## Mitigation

Restrict management to jump hosts; MFA; VPN; firewall allowlists; disable remote admin where possible.

## Replication Steps

1. Scan scope for management ports.
2. Verify authentication and encryption.
3. Attempt connection from untrusted network segment.
4. Document exposed services.
5. Recommend network segmentation.

## References

- https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/

## Detection

**Network:** Detect inbound 3389/22/5985 from Internet; geo-anomaly on admin logins.

## Guidance

Network and infrastructure assessments.
