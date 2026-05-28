# Operator Notes — Acme Corp Portal (ENG-2025-DEMO)

**Date:** 2025-05-28
**Operator:** mbhowmick
**Target:** portal.acme-demo.com (10.0.1.50)
**Scope:** Web application pentest — portal only, no infrastructure

---

## Session notes

Started with cred pair jsmith / Winter2025! provided by client. App is a Ruby on Rails employee portal — confirmed from error pages and cookie format.

Login form at /api/login takes JSON, returns JWT-style session cookie. No rate limiting observed — tried 20+ login attempts with no lockout or CAPTCHA.

### SQLi in login

Tested username field with single quote — got a raw Postgres error back with the full query. The app concatenates user input directly into a SELECT statement. No WAF in front of this endpoint.

Second payload `admin' OR 1=1-- -` bypassed auth entirely and returned an admin session. The session cookie decoded shows `{"uid":1,"role":"admin"}` — role is set server-side based on the query result, not from a separate lookup.

This is critical — unauthenticated attacker gets full admin access.

### XSS in search

Search page at /search reflects the `q` parameter directly into an H1 tag. No encoding, no CSP header. Standard `<script>alert(document.domain)</script>` fires immediately. Tested in Firefox and Chrome — both execute. Screenshot saved to screenshots/xss-search-alert.png.

Stored XSS not tested — search doesn't persist. But if there's a saved searches feature this could escalate.

### IDOR in profile API

Profile endpoint is /api/users/{id}/profile. Authenticated as user 42 (jsmith), changed the ID to 1 — got back full profile for Admin User including email, role, and partial SSN. Iterated IDs 1-5, all returned data. No authorization check on the user ID parameter.

Response includes SSN (masked but still `***-**-5678` format) and salary. This is PII exposure — regulatory implications depending on jurisdiction.

### Other observations

- No HTTPS redirect on port 80 — app is accessible over HTTP
- Session cookie is HttpOnly but not Secure flag
- No Content-Security-Policy header anywhere
- /api/users endpoint without ID returns 404, not 403 — information disclosure about valid routes
- Admin panel at /admin accessible after SQLi bypass — did not test further per RoE
