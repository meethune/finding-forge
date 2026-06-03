---
title: "CWE-22 — Path Traversal"
cwe_ids:
  - CWE-22
tags:
  - web
  - cwe-22
finding_type: Web
severity:
  rating: High
---

## Description

The application uses user input to construct file paths without restricting to intended directories. CWE-22 ranked #6.

## Impact

Arbitrary file read/write, configuration disclosure, or code execution via writable paths.

## Mitigation

Allowlist filenames; canonicalize paths; chroot/jail; deny parent directory sequences; least-privilege file permissions.

## Replication Steps

1. Supply ../ sequences in file parameters.
2. Attempt to read sensitive files (e.g., /etc/passwd, web.config).
3. Test write paths if applicable.
4. Confirm content in response or side channel.
5. Document vulnerable parameter.

## References

- https://cwe.mitre.org/data/definitions/22.html

## Guidance

Parent: A01 and A05. Also CWE-36, CWE-23 variants.
