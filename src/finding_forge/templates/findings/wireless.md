---
title: "Wireless — Weak Wi-Fi Security Configuration"
tags:
  - wireless
finding_type: Wireless
severity:
  rating: High
---

## Description

Wireless networks use deprecated protocols (WEP, WPA), weak PSKs, or lack client isolation enabling lateral movement.

## Impact

Passive capture of credentials; unauthorized network access; pivot to internal segments.

## Mitigation

WPA3-Enterprise or WPA2-Enterprise; strong PSK policy; disable legacy protocols; network segmentation and monitoring.

## Replication Steps

1. Survey wireless beacons in scope.
2. Assess encryption and authentication mode.
3. Test client isolation and guest network separation.
4. Attempt authorized crack of weak PSK in lab.
5. Document configuration.

## References

- https://owasp.org/www-project-mobile-top-10/

## Detection

**Network:** Detect rogue APs; monitor for deauth floods and evil twin SSIDs.

## Guidance

Wireless penetration tests only.
