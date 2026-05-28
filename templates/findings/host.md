---
title: "Host — Missing Security Patches"
tags:
  - host
finding_type: Host
severity:
  rating: High
---

## Description

Operating systems or applications on hosts lack critical security updates, exposing known CVEs.

## Impact

Exploitation of public exploits for local privilege escalation or remote access.

## Mitigation

Automated patch management; vulnerability scanning; emergency patch process; EOL software replacement.

## Replication Steps

1. Enumerate OS and package versions.
2. Correlate with CVE databases.
3. Identify missing critical patches.
4. Validate exploitability in lab if authorized.
5. Document patch gap.

## References

- https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/

## Detection

**Host:** Vulnerability scanner results; WSUS/SCCM compliance reports; EDR patch status.

## Guidance

Vulnerability assessment finding; link to specific CVE in report instance.
