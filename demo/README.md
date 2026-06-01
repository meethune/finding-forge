# Demo: Acme Corp Portal Engagement

Fictional engagement against `portal.acme-demo.com` with three findings:

1. **SQL Injection** in `/api/login` — error-based, leads to auth bypass
2. **Reflected XSS** in `/search` — unencoded `q` parameter
3. **IDOR** in `/api/users/{id}/profile` — horizontal privilege escalation, PII exposure

## Setup

The MCP server must be registered (user-scoped so it works from any directory):

```bash
# IBM Bob
bob mcp add --scope user finding-forge \
  uv run --project /path/to/finding-forge finding-forge-mcp

# Claude Code
claude mcp add --scope user finding-forge -- \
  uv run --project /path/to/finding-forge finding-forge-mcp
```

## Demo Script

Open IBM Bob, Claude Code, or any MCP client from **any directory** and walk through these steps. Each quoted block is something you say to the AI.

---

### Step 1: Set the scene

> "I just finished a web app pentest against portal.acme-demo.com. I have a Burp proxy export and my session notes. Let me show you what I found."

Then share the operator notes — either paste them or point the AI at the file:

> "Here are my operator notes from the session" *(paste contents of operator-notes.md)*

Shows: The AI now has the operator's narrative context — what was tested, what was found, and the operator's assessment of severity. This is the human judgment layer.

---

### Step 2: Extract Burp data

> "Now parse the Burp export at demo/burp-export.xml from the finding-forge project, scoped to portal.acme-demo.com"

Shows: 7 in-scope requests extracted, 1 out-of-scope CDN request filtered out. The AI sees the raw HTTP requests/responses that corroborate the operator's notes — the SQLi error, XSS reflection, and IDOR responses.

---

### Step 3: Match a template

> "What templates match SQL injection?"

Shows: `match_finding_templates` returns `cwe-89` (SQL Injection) and related templates.

---

### Step 4: Calculate CVSS for the SQLi

> "Calculate the CVSS score for this SQL injection. It's network-accessible, low complexity, no privileges needed, no user interaction, scope unchanged, confidentiality and integrity are high, no availability impact."

Shows: The AI calls `calculate_cvss` with `AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:H, A:N` and gets back the exact vector string (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`), score (9.1), and rating (Critical). No guessing — deterministic math.

---

### Step 5: Draft the SQLi finding

> "Draft a finding for the SQL injection I described in my notes. The Burp data has the actual requests and error responses. Use the cwe-89 template and the CVSS score you just calculated."

Shows: The AI combines the operator's narrative (from notes) with the raw HTTP evidence (from Burp), the template's severity baseline, and the deterministic CVSS score to produce a concise, evidence-anchored finding.

---

### Step 6: Draft the XSS finding (with screenshot)

> "Now draft the reflected XSS finding. Here's the screenshot showing the alert firing in the browser" *(drop or reference demo/screenshots/xss-search-alert.png)*
>
> "My notes and the Burp export have the rest of the details. Use the cwe-79 template."

Shows: The AI sees the screenshot (multimodal clients like Claude Code can read images), combines it with the operator notes and Burp request/response to produce a finding that references visual proof of execution — not just the raw HTML.

---

### Step 7: Draft the IDOR finding

> "Draft the IDOR finding. My notes mention PII exposure including SSN and salary data. The Burp requests show I accessed profiles for users 1 and 2 as user 42. Use the cwe-639 template."

---

### Step 8: Export to Cervantes

> "Export all three findings in cervantes format so I can import them"

Shows: `export_finding` with `fmt=cervantes` produces semicolon-delimited CSV matching Cervantes' 20-column import format.

**Cervantes import path:** In Cervantes, go to the project, select Import Vulnerabilities, choose CSV, and upload the file. Findings appear with severity, CVSS, description, remediation, and proof of concept already populated.

> **Caveat for the demo:** Cervantes' CSV import is flaky — it can fail silently or reject valid rows depending on version and database state. The export format is correct per the Cervantes schema, but import results may vary. Have a fallback plan (show the CSV content and explain the column mapping) in case the live import doesn't cooperate.

---

### Step 9: Export as markdown (alternative)

> "Also export the SQLi finding as markdown for the executive summary"

Shows: Same finding, different format — Markdown for Word/Google Docs, Cervantes CSV for the findings database.

---

### Step 10: Batch generate all findings

> "Using finding forge tools, examine all the files in this directory and write each individual finding as markdown to disk. Make sure to include screenshots and not just reference them. Use the export_findings tool to generate the markdown."

Shows: The AI autonomously scans the directory, parses the Burp export with `extract_burp`, reads the operator notes and screenshot, matches templates, calculates CVSS for each finding, and writes individual markdown files to disk — all from a single prompt. This is the complete end-to-end workflow.

---

## What the audience sees

- **Deterministic CVSS scoring** — the `calculate_cvss` tool computes exact scores from metrics, no AI guessing
- **Three evidence types in one workflow** — Burp HTTP data, operator notes, and screenshots all feed into finding drafts
- **Cervantes integration** — export findings as Cervantes-compatible CSV for bulk import (note: Cervantes' import is flaky, YMMV)
- **No AI provider lock-in** — the same tools work in Claude Code, IBM watsonx, Gemini, or any MCP client
- **78 templates** covering OWASP Top 10:2025, LLM Top 10:2025, and CWE Top 25:2025
- **Evidence integrity** — the AI references actual requests/responses, never fabricates
- **Concise output** — no boilerplate code samples or tutorials, just actionable findings
- **Any reporting platform** — export to JSON, CSV, Markdown, or Cervantes CSV

## Files

- `burp-export.xml` — Burp proxy history export (8 requests, 3 vulnerabilities)
- `operator-notes.md` — Free-form session notes with observations, context, and severity assessments
- `screenshots/xss-search-alert.png` — Browser screenshot of XSS alert execution
- `reproductions/xss-search.html` — Local HTML reproduction of the vulnerable search response
