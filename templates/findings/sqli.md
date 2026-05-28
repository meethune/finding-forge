---
title: SQL Injection
cwe_ids:
  - CWE-89
tags:
  - sqli
  - injection
  - database
  - owasp-a03
severity:
  rating: High
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
  cvss_score: 9.1
  justification: "Unauthenticated network-accessible injection enabling full database read/write"
---

## Description

The application is vulnerable to SQL injection, allowing an attacker to manipulate database queries by injecting arbitrary SQL code through user-controlled input. This occurs when user input is concatenated directly into SQL statements without proper parameterization or input validation.

## Impact

Successful exploitation allows an attacker to read, modify, or delete arbitrary data in the database. Depending on database configuration and privileges, this may also enable operating system command execution, file system access, or lateral movement to other systems. Sensitive data such as credentials, personal information, and business records may be fully compromised.

## Mitigation

- Use parameterized queries (prepared statements) for all database interactions
- Apply the principle of least privilege to database accounts used by the application
- Implement input validation as a defense-in-depth measure (not a primary control)
- Deploy a web application firewall (WAF) as an additional detection layer
- Regularly review and test database access code for injection vulnerabilities

## Replication Steps

1. Identify an input field that interacts with a database query
2. Submit a single quote character (') and observe the application response for errors
3. Craft a boolean-based payload (e.g., `' OR 1=1--`) and confirm altered behavior
4. Extract data using UNION-based or error-based techniques as appropriate
5. Document the injection point, payload, and extracted data

## References

- https://cwe.mitre.org/data/definitions/89.html
- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Detection

- Monitor database logs for anomalous query patterns or errors
- Deploy WAF rules to detect common SQL injection payloads
- Enable application-level logging of all database queries with parameterized values
- Use database activity monitoring (DAM) tools to alert on suspicious query behavior
