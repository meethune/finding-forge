---
title: Reflected Cross-Site Scripting (XSS)
cwe_ids:
  - CWE-79
tags:
  - xss
  - reflected
  - injection
  - owasp-a03
severity:
  rating: Medium
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
  cvss_score: 6.1
  justification: "Requires user interaction (clicking a crafted link) but crosses security boundary"
---

## Description

The application reflects user-supplied input in HTTP responses without proper encoding or sanitization, enabling an attacker to inject arbitrary JavaScript code. When a victim visits a crafted URL, the injected script executes in the context of the victim's browser session with the application.

## Impact

An attacker can steal session tokens, capture credentials, redirect users to malicious sites, deface the application, or perform actions on behalf of the victim. In environments with sensitive data or administrative interfaces, this can lead to full account takeover.

## Mitigation

- Encode all user-supplied output using context-appropriate encoding (HTML entity, JavaScript, URL, CSS)
- Implement a strict Content Security Policy (CSP) to limit script execution sources
- Use HTTP-only and Secure flags on session cookies to reduce theft impact
- Apply input validation as a defense-in-depth measure
- Use modern frameworks that auto-escape output by default

## Replication Steps

1. Identify a parameter that is reflected in the HTTP response
2. Submit a test payload (e.g., `<script>alert(document.domain)</script>`)
3. Observe whether the payload is rendered unencoded in the response
4. Confirm script execution in a browser
5. Document the injection point, payload, and execution context

## References

- https://cwe.mitre.org/data/definitions/79.html
- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Detection

- Deploy WAF rules to detect common XSS payloads in request parameters
- Monitor Content Security Policy violation reports
- Enable browser-side XSS protection headers where supported
- Review application logs for encoded script patterns in user input
