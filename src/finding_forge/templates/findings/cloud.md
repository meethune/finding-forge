---
title: "Cloud — Publicly Exposed Object Storage"
tags:
  - cloud
finding_type: Cloud
severity:
  rating: High
---

## Description

Cloud storage buckets or blobs (S3, Azure Blob, GCS) allow anonymous read or list due to misconfigured ACLs or policies. Aligns with OWASP A02 misconfiguration.

## Impact

Mass data exfiltration of backups, logs, or customer data; regulatory breach.

## Mitigation

Block public access by default; least-privilege IAM; encryption; logging; periodic policy scans.

## Replication Steps

1. Enumerate storage URLs from apps and DNS.
2. Attempt anonymous list/get.
3. Document exposed objects (redact sensitive content in report).
4. Verify account-level public access blocks.
5. Recommend policy fixes.

## References

- https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

## Guidance

Use for cloud pen tests. Not a single CWE rank but common engagement finding.
