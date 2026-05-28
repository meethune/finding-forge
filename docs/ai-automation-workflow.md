# AI-Assisted Penetration Test Reporting — Tool-Agnostic Workflow

## Overview

This document describes an AI-enhanced automation workflow for penetration testing that works with **any** reporting platform (Cervantes, Ghostwriter, Dradis, Plextrac, PlexTrac, Faraday, or even Word/Excel/Google Docs). 

The core idea: **Automate evidence collection and finding drafting so operators spend time on analysis, not data entry.**

---

## The Universal Pentest Reporting Problem

Regardless of which reporting tool you use, the workflow has the same pain points:

```
┌──────────────────────────────────────────────────────────────┐
│ During Testing                                               │
│   • Burp Suite generates hundreds/thousands of requests      │
│   • Operator takes screenshots                               │
│   • Operator keeps notes (text files, OneNote, memory)       │
│   • Logs accumulate (nmap, sqlmap, custom scripts)           │
└──────────────────────────────────────────────────────────────┘
                            ↓
                   (Testing finishes)
                            ↓
┌──────────────────────────────────────────────────────────────┐
│ Reporting Time — THE PAINFUL RECONSTRUCTION                  │
│   1. Hunt for evidence files across folders                  │
│   2. Review Burp history to find "that request"              │
│   3. Open blank finding form (or template)                   │
│   4. Write description from memory/notes                     │
│   5. Copy-paste request/response (formatting often breaks)   │
│   6. Upload screenshots one-by-one                           │
│   7. Write replication steps                                 │
│   8. Calculate CVSS score (inconsistent interpretation)      │
│   9. Write impact and mitigation                             │
│   10. Repeat for each finding                                │
│                                                              │
│ TIME PER FINDING: 20-40 minutes                              │
└──────────────────────────────────────────────────────────────┘
```

### Why This Is Slow

1. **Evidence scattered** — Screenshots, logs, notes in different locations
2. **Manual reconstruction** — Writing from memory, not contemporaneous capture
3. **Blank page syndrome** — Starting from scratch even for common findings
4. **Formatting corruption** — Copy-paste mangles code/request formatting
5. **CVSS ambiguity** — Metric definitions subject to interpretation, inconsistent across team
6. **Repetitive writing** — Same mitigation language written dozens of times

---

## The Automation Solution (Tool-Agnostic)

### Core Principle

**Capture evidence automatically during/after testing, then use AI to draft findings from structured data + reusable templates.**

This works with ANY reporting platform because the automation happens BEFORE you touch the reporting tool.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Evidence Sources (Universal)                                │
│   • Burp Suite project/history/scanner                      │
│   • Screenshots folder                                      │
│   • Tool logs (nmap, sqlmap, nuclei, etc.)                  │
│   • Operator notes (conversational or structured)           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Automation Layer (Python + AI)                              │
│                                                              │
│ 1. Evidence Aggregation Script                              │
│    • Reads Burp project/history for target scope            │
│    • Collects screenshots from standard folder              │
│    • Parses tool logs (XML, JSON, text)                     │
│    • Prompts operator: "What did you find?"                 │
│                                                              │
│ 2. Structured Data Generation                               │
│    • Converts Burp requests → formatted evidence            │
│    • Links screenshots to findings by timestamp/name        │
│    • Tags findings by type (sqli, xss, authz, etc.)         │
│    • Stores in intermediate format (JSON, CSV, Markdown)    │
│                                                              │
│ 3. AI Finding Drafting                                      │
│    • Operator selects finding type from evidence            │
│    • AI retrieves matching template from library            │
│    • AI drafts complete finding:                            │
│      - Description populated from evidence                  │
│      - Replication steps from Burp requests                 │
│      - Screenshots embedded/linked                          │
│      - CVSS score suggested with FIRST.org definitions      │
│      - Impact/mitigation from template                      │
│    • Outputs draft in reporting-tool format                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Reporting Platform (Any Tool)                               │
│   • Cervantes: Import CSV or manual copy-paste              │
│   • Ghostwriter: GraphQL API or CSV import                  │
│   • Dradis/Plextrac: REST API or template upload            │
│   • Word/Excel: Direct export                               │
│   • Google Docs: API upload                                 │
│                                                              │
│ Operator reviews/edits draft, then saves                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Workflow: End-of-Session Evidence Capture

### Step 1: During Testing (No Change)

Operator tests however they prefer:
- Use Burp Suite as normal
- Save screenshots to a standard folder: `~/screenshots/<engagement-name>/`
- Optional: Flag interesting Burp requests with colors/comments
- Optional: Keep rough notes

**No context switching, no manual logging during testing.**

---

### Step 2: End of Testing Session (NEW — 5 minutes)

Operator runs one command:

```bash
pentest-capture --target "https://app.example.com" \
                --engagement "CLIENT-2026-05" \
                --burp-project "~/burp/client-webapp.burp" \
                --screenshots "~/screenshots/client-webapp/"
```

The script:

1. **Extracts Burp data:**
   - Filters Proxy history to target scope
   - Extracts Scanner findings
   - Captures interesting requests (flagged, 4xx/5xx responses, high Scanner severity)
   
2. **Prompts operator (conversational):**
   ```
   AI: "What did you test today? What did you find?"
   
   Operator: "Tested login and password reset. Found SQL injection 
             in the username parameter—bypassed auth. Also found weak 
             session tokens and missing rate limiting on login."
   ```

3. **Generates structured evidence:**
   - Parses operator's conversational input
   - Tags findings: `vuln:sqli`, `vuln:weak-session`, `vuln:rate-limit`
   - Links Burp requests to finding types
   - Associates screenshots by timestamp/filename patterns
   - Outputs JSON:
   
   ```json
   {
     "engagement": "CLIENT-2026-05",
     "target": "https://app.example.com",
     "date": "2026-05-28",
     "findings": [
       {
         "type": "sqli",
         "title": "SQL Injection in Login",
         "evidence": {
           "request": "POST /login HTTP/1.1\nusername=admin'--&password=test",
           "response": "HTTP/1.1 200 OK\n...",
           "screenshots": ["login-sqli-bypass.png"],
           "operator_notes": "Bypassed auth with ' OR '1'='1"
         }
       }
     ]
   }
   ```

**Time: 2-5 minutes** (conversational summary + script execution)

---

### Step 3: Finding Drafting (AI-Assisted)

Operator reviews structured evidence:

```bash
pentest-draft --evidence evidence.json --template-library ./templates/
```

For each finding in evidence file:

1. **AI suggests templates:**
   ```
   Finding: SQL Injection in Login
   
   Suggested templates:
   1. CWE-89 — SQL Injection (OWASP A05:2025)
   2. OWASP A05:2025 — Injection (generic)
   3. Authentication Bypass via SQLi
   
   Select template [1-3]: 1
   ```

2. **AI drafts complete finding:**

   ```markdown
   # SQL Injection in Login Username Parameter
   
   ## Description
   The application's login functionality is vulnerable to SQL injection 
   via the `username` parameter. An attacker can manipulate the SQL query 
   to bypass authentication without valid credentials.
   
   ## Severity
   **High** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.2)
   
   ### CVSS Justification (FIRST.org definitions)
   - Attack Vector (AV:N): Exploitable remotely over the network
   - Attack Complexity (AC:L): No special conditions required
   - Privileges Required (PR:N): Unauthenticated attack
   - User Interaction (UI:N): No user interaction needed
   - Scope (S:U): Unchanged—impacts only the vulnerable application
   - Confidentiality (C:H): Access to all user data
   - Integrity (I:H): Can modify database records
   - Availability (A:N): No DoS demonstrated
   
   ## Impact
   Successful exploitation allows an attacker to:
   - Bypass authentication and access any user account
   - Read, modify, or delete database records
   - Potentially execute operating system commands if database 
     permissions allow (e.g., xp_cmdshell in MSSQL)
   
   ## Evidence
   
   ### Request
   ```http
   POST /login HTTP/1.1
   Host: app.example.com
   Content-Type: application/x-www-form-urlencoded
   
   username=admin'--&password=test
   ```
   
   ### Response
   ```http
   HTTP/1.1 200 OK
   Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   
   {"status":"success","redirect":"/dashboard","role":"admin"}
   ```
   
   ### Screenshot
   ![Authentication bypass via SQL injection](login-sqli-bypass.png)
   
   ## Replication Steps
   1. Navigate to https://app.example.com/login
   2. Enter the following payload in the username field:
      ```
      admin'--
      ```
   3. Enter any value in the password field
   4. Submit the login form
   5. Observe successful authentication as the `admin` user without 
      valid credentials
   
   ## Mitigation
   - **Use parameterized queries (prepared statements)** for all database 
     interactions. Never concatenate user input into SQL strings.
   - Implement an ORM (e.g., SQLAlchemy, Hibernate, Entity Framework) 
     that handles parameterization automatically.
   - Apply least-privilege database accounts—the application should not 
     run with `db_owner` or equivalent permissions.
   - Deploy a Web Application Firewall (WAF) as defense-in-depth, not 
     primary control.
   - Code review all database query construction.
   
   ## References
   - https://owasp.org/Top10/2025/A05_2025-Injection/
   - https://cwe.mitre.org/data/definitions/89.html
   - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
   
   ## Detection
   - Monitor for SQL error messages in application logs
   - Alert on repeated 500 errors from database layer
   - Detect SQL metacharacters in authentication parameters (', --, ;)
   - Use database query monitoring to flag unexpected UNION, OR, or 
     comment sequences in auth queries
   ```

3. **Operator reviews/edits:**
   - Verify technical accuracy
   - Adjust severity if needed
   - Add context-specific details
   - Fix any AI hallucinations

4. **Export to reporting tool format:**
   ```bash
   # For Cervantes CSV import
   pentest-draft --format cervantes-csv --output findings.csv
   
   # For Ghostwriter GraphQL
   pentest-draft --format ghostwriter --output findings.json
   
   # For Word report
   pentest-draft --format docx --output report.docx
   
   # For Markdown (Dradis/Plextrac)
   pentest-draft --format markdown --output findings/
   ```

**Time per finding: 5-10 minutes** (review/edit AI draft) vs 20-40 minutes (write from scratch)

---

## Component Breakdown

### 1. Burp Data Extraction (`burp_extract.py`)

**Input:** Burp project file or Proxy history  
**Output:** Structured JSON with requests, responses, Scanner findings

```python
# Pseudocode
def extract_burp_data(project_file, target_scope):
    """
    Reads Burp project file, filters to scope, extracts:
    - Proxy history (requests/responses)
    - Scanner findings (with severity)
    - Interesting requests (4xx, 5xx, flagged)
    """
    requests = parse_burp_project(project_file)
    filtered = filter_by_scope(requests, target_scope)
    interesting = flag_interesting(filtered)
    scanner = extract_scanner_findings(project_file)
    
    return {
        "requests": interesting,
        "scanner_findings": scanner,
        "scope": target_scope
    }
```

**Tool-agnostic:** Works with any reporting platform—outputs standard JSON.

---

### 2. Evidence Aggregation (`evidence_capture.py`)

**Input:** Burp data, screenshots folder, operator notes  
**Output:** Structured evidence file linking all sources

```python
# Pseudocode
def aggregate_evidence(burp_data, screenshot_dir, operator_notes):
    """
    Combines evidence from multiple sources:
    - Burp requests/responses
    - Screenshots (linked by timestamp/filename)
    - Operator conversational notes (parsed by AI)
    """
    findings = parse_operator_notes(operator_notes)  # AI extracts finding types
    
    for finding in findings:
        finding["evidence"] = {
            "requests": match_burp_requests(burp_data, finding),
            "screenshots": match_screenshots(screenshot_dir, finding),
            "scanner": match_scanner_findings(burp_data, finding)
        }
    
    return findings
```

**Tool-agnostic:** Outputs JSON/CSV that any tool can import.

---

### 3. Finding Drafting (`ai_drafter.py`)

**Input:** Evidence file, findings library templates  
**Output:** Complete finding draft in requested format

```python
# Pseudocode
def draft_finding(evidence, template_library, output_format):
    """
    Uses AI to draft finding from evidence + template:
    1. Operator selects finding type
    2. AI retrieves matching template
    3. AI populates template with evidence
    4. AI suggests CVSS score
    5. Outputs in requested format (CSV, JSON, Markdown, DOCX)
    """
    template = search_template_library(evidence["type"], template_library)
    
    prompt = f"""
    Draft a penetration test finding using this template and evidence.
    
    Template: {template}
    
    Evidence:
    - Request: {evidence["request"]}
    - Response: {evidence["response"]}
    - Operator notes: {evidence["notes"]}
    - Screenshots: {evidence["screenshots"]}
    
    Include CVSS score with FIRST.org metric justification.
    Format output as {output_format}.
    """
    
    draft = ai_complete(prompt)
    return format_output(draft, output_format)
```

**Tool-agnostic:** Outputs to any format via `output_format` parameter.

---

### 4. Findings Template Library

**Universal collection** of reusable finding templates:

```
templates/
├── web/
│   ├── sqli.md
│   ├── xss.md
│   ├── csrf.md
│   ├── authz-bypass.md
│   └── ...
├── cloud/
│   ├── public-s3.md
│   ├── overprivileged-iam.md
│   └── ...
├── infrastructure/
│   ├── missing-patches.md
│   ├── weak-passwords.md
│   └── ...
└── owasp/
    ├── A01-broken-access-control.md
    ├── A05-injection.md
    └── ...
```

Each template includes:
- Standard description
- Impact language
- Mitigation guidance
- References (OWASP, CWE, CVE)
- CVSS baseline
- Detection techniques

**Tool-agnostic:** Templates are Markdown—can be imported to any platform or rendered directly.

---

## Benefits (Any Reporting Platform)

| Benefit | How Automation Helps | Tool Requirement |
|---------|---------------------|------------------|
| **Faster finding creation** | AI drafts from template + evidence (5-10 min vs 20-40 min) | None—works with any tool |
| **Consistent quality** | Templates ensure complete findings (description, impact, mitigation, references) | None—templates are standalone files |
| **No formatting corruption** | Evidence extracted programmatically, not copy-pasted | None—script handles formatting |
| **Evidence completeness** | All screenshots/requests linked automatically | None—evidence aggregated before tool entry |
| **CVSS consistency** | AI provides FIRST.org definitions for each metric | None—scoring happens before tool entry |
| **Reusable knowledge** | Findings library grows with each engagement | None—library is file-based |
| **Reduced blank-page time** | Never start from scratch—always template-based | None—templates work anywhere |

---

## Implementation Roadmap

### Phase 1: Manual Workflow with AI Drafting (Week 1)
**Goal:** Prove AI can draft findings faster than humans from scratch.

**What to build:**
- Findings template library (Markdown files)
- Simple script: Paste Burp request + notes → AI drafts finding
- No Burp automation yet—operator provides evidence manually

**Success metric:** Drafting one finding takes <10 minutes vs 20-40 minutes

**Tool integration:** Copy-paste AI draft into Cervantes/current tool

---

### Phase 2: Burp Extraction + Evidence Aggregation (Week 2-3)
**Goal:** Automate evidence collection—no manual copy-paste.

**What to build:**
- Burp project parser (reads `.burp` files or Proxy XML export)
- Screenshot linking (by timestamp/filename conventions)
- Evidence aggregation script (combines Burp + screenshots + notes)

**Success metric:** End-of-session capture takes <5 minutes, evidence complete

**Tool integration:** Import generated CSV/JSON into reporting tool or copy-paste Markdown

---

### Phase 3: Full Automation Pipeline (Week 4)
**Goal:** One command from testing to draft findings.

**What to build:**
- `pentest-capture` command (Burp + screenshots + conversational notes → evidence.json)
- `pentest-draft` command (evidence.json + templates → formatted findings)
- Export to multiple formats (CSV, JSON, Markdown, DOCX)

**Success metric:** 10 findings drafted in 1 hour (vs 5+ hours manual)

**Tool integration:** Choose format based on your reporting tool's import capability

---

### Phase 4: Reporting Tool Integration (Optional)
**Goal:** Direct API integration for zero copy-paste.

**What to build (pick your tool):**
- **Cervantes:** CSV bulk import or REST API
- **Ghostwriter:** GraphQL mutations via MCP server
- **Dradis/Plextrac:** REST API upload
- **Word/Google Docs:** Direct document generation

**Success metric:** Findings flow from Burp → reporting tool with no manual steps

---

## Tool-Specific Integration Notes

### Cervantes
- **Import method:** CSV upload to findings module
- **CSV headers:** `title,description,severity,impact,mitigation,replication_steps,references`
- **Limitations:** Screenshots must be uploaded separately (no CSV support)
- **Workaround:** AI drafts finding, operator copy-pastes Markdown, manually uploads screenshots

### Ghostwriter
- **Import method:** GraphQL API or CSV to findings library
- **API advantages:** Can link screenshots, attach to oplog entries, create full project structure
- **MCP server:** Enables natural-language Claude Code interaction
- **Best fit:** If also adopting oplog workflow

### Dradis / Plextrac / Faraday
- **Import method:** REST API or Markdown file import
- **Template format:** Most support Markdown or custom templates
- **Integration:** POST findings via API with attachments

### Word / Excel / Google Docs
- **Export method:** Generate documents directly from templates
- **Python libraries:** `python-docx` (Word), `openpyxl` (Excel), Google Docs API
- **Best fit:** Small teams or when no dedicated reporting platform exists

---

## Example: Complete Workflow (Cervantes Current State)

### Before Automation

**Operator workflow for one SQLi finding:**

1. Finish testing (30 min active testing)
2. Open Cervantes, click "New Finding"
3. Search Burp history for "that SQLi request" (5 min)
4. Copy-paste request into Cervantes (formatting breaks, fix manually: 3 min)
5. Write description from memory (5 min)
6. Write replication steps (5 min)
7. Google "SQL injection CVSS score" (3 min)
8. Write impact (3 min)
9. Write mitigation (3 min)
10. Hunt for screenshot file (2 min)
11. Upload screenshot (1 min)
12. Review and save (2 min)

**Total: ~32 minutes per finding**

---

### After Automation (Still Using Cervantes)

**Operator workflow for one SQLi finding:**

1. Finish testing (30 min active testing)
2. Run: `pentest-capture --target https://app.example.com`
3. AI asks: "What did you find?"
4. Operator: "SQL injection in login username field" (30 sec)
5. Script extracts Burp data, links screenshots, generates evidence.json (2 min)
6. Run: `pentest-draft --evidence evidence.json --format markdown`
7. AI drafts complete finding with CVSS, mitigation, references (1 min)
8. Operator reviews AI draft (3 min)
9. Copy-paste Markdown into Cervantes (1 min)
10. Upload screenshots (auto-linked in Markdown: 1 min)
11. Save (30 sec)

**Total: ~9 minutes per finding (64% time savings)**

**No Cervantes replacement required.**

---

## Extending to Ghostwriter (Optional Next Step)

If automation proves valuable with Cervantes, Ghostwriter adds:

1. **Oplog integration** — Evidence already in system during testing (no end-of-session capture needed)
2. **Native API** — Findings imported via GraphQL (no copy-paste)
3. **Deconfliction tracking** — Timeline answers "was that you?" instantly
4. **Findings library versioning** — Templates evolve with team knowledge
5. **Multi-engagement asset tracking** — Domains/servers checked out to prevent conflicts

**Migration pitch:** "Automation works great with Cervantes. Ghostwriter eliminates the copy-paste step and adds real-time activity logging."

---

## Cost-Benefit Analysis

### Investment Required

| Component | Effort | Skill Required |
|-----------|--------|----------------|
| Findings template library | 2-4 hours (adapt OWASP/CWE examples) | Markdown, pentest domain knowledge |
| Burp extraction script | 4-8 hours | Python, Burp file formats |
| Evidence aggregation script | 4-6 hours | Python, AI API (Claude/OpenAI) |
| AI drafting integration | 2-4 hours | AI prompting, template merging |
| Export formatters | 2-4 hours per format | Python, target tool's import format |
| **Total** | **14-26 hours** | **Mid-level Python + pentest experience** |

### Return on Investment

**Per engagement (10 findings):**
- Manual: 320 minutes (5.3 hours)
- Automated: 90 minutes (1.5 hours)
- **Savings: 3.8 hours per engagement**

**Per year (50 engagements):**
- Manual: 265 hours
- Automated: 75 hours
- **Savings: 190 hours (4.75 weeks of FTE time)**

**Break-even: After 2-3 engagements** (assuming 26-hour build time)

---

## Security and Quality Considerations

### AI Limitations

**AI can hallucinate or make mistakes:**
- CVSS scores may be incorrect (always review)
- Mitigation steps may be generic or incomplete
- Technical details may be inaccurate

**Mitigation:**
- Operator ALWAYS reviews AI drafts (never auto-publish)
- Templates include references (OWASP, CWE) for verification
- CVSS definitions embedded in prompts (FIRST.org official text)
- Team review process unchanged (lead reviews findings)

### Evidence Integrity

**Never fabricate or modify evidence:**
- Burp requests/responses extracted as-is (no editing)
- Screenshots linked, not altered
- Operator notes conversational, not structured by AI (prevents leading)

**Audit trail:**
- Raw evidence files preserved (evidence.json, Burp exports)
- AI prompts logged (for transparency)
- Operator edits tracked (diff between AI draft and final)

---

## Frequently Asked Questions

### Q: Does this work if we don't use Burp Suite?
**A:** Yes—the automation pattern works with any evidence source:
- **Web testing:** ZAP, Caido, manual cURL logs
- **Network testing:** Nmap XML, Nessus exports
- **Cloud testing:** ScoutSuite JSON, Prowler reports
- **Infrastructure:** OpenVAS, Qualys exports

Replace `burp_extract.py` with a parser for your tool's output format.

---

### Q: What if operators don't trust AI-generated content?
**A:** Operators review/edit all drafts—AI provides structure, operator verifies accuracy. Same as using a template today, but the template is pre-filled.

---

### Q: Can this be used for compliance/formal audits?
**A:** Yes, with caveats:
- Operator must review all AI content (document this in methodology)
- Preserve raw evidence files for audit trail
- CVSS scores must be verified (AI suggestions are starting points)
- Some frameworks (PCI-DSS, FedRAMP) may require human attestation

---

### Q: What about junior operators who don't know what to look for?
**A:** AI can help:
- Burp Scanner findings → AI suggests finding type and template
- Junior describes what they did → AI identifies potential vulnerabilities
- Template library provides learning material (impact, mitigation, references)

**Not a replacement for training—augments junior capability.**

---

### Q: How do we maintain the findings template library?
**A:** Treat it like code:
- Version control (Git)
- Lead/senior operators review template updates
- After each engagement, capture new finding types
- Quarterly review: prune outdated, add emerging threats

---

### Q: What if our reporting tool doesn't have an API?
**A:** Export to formats your tool accepts:
- Markdown (import to most tools)
- CSV (import to Cervantes, Excel, Dradis)
- Word DOCX (manual merge to report)
- Copy-paste (still faster than writing from scratch)

---

### Q: Can we share our findings library with other teams/community?
**A:** Yes—sanitize client-specific details, publish to GitHub. Many teams maintain public finding libraries (e.g., HackTricks, PayloadsAllTheThings).

---

## Next Steps

### Step 1: Validate with One Operator, One Engagement
- Pick a small engagement (3-5 findings)
- Build simple AI drafting script (no Burp automation yet)
- Operator manually provides evidence, AI drafts finding
- Measure time savings vs manual Cervantes entry

### Step 2: Gather Feedback
- Was AI draft accurate?
- Did it save time?
- What would make it more useful?

### Step 3: Automate Evidence Collection
- Build Burp extraction script
- Add screenshot linking
- Test end-of-session capture workflow

### Step 4: Scale to Team
- If successful, roll out to all operators
- Build findings template library collaboratively
- Integrate with current reporting tool (Cervantes)

### Step 5 (Optional): Evaluate Ghostwriter
- If automation proves valuable, demo Ghostwriter as "this, but better"
- Run parallel engagement (Cervantes + Ghostwriter)
- Let operators choose based on experience

---

## Conclusion

AI-assisted automation reduces penetration test reporting time by 60-70% **regardless of which reporting platform you use**. The value comes from:

1. **Automated evidence collection** (Burp + screenshots + logs)
2. **Reusable findings templates** (consistent quality)
3. **AI drafting** (structure + evidence + CVSS in minutes)

This workflow is **tool-agnostic**—works with Cervantes, Ghostwriter, Word, or anything else.

**Start small:** Prove AI drafting saves time with current tools.  
**Scale incrementally:** Add automation as team sees value.  
**Migrate when ready:** Ghostwriter (or another platform) becomes a natural next step, not a forced change.

---

## Appendix: Reference Implementation

See repository structure:

```
operator-toolkit/
├── scripts/
│   ├── burp_extract.py          # Burp data extraction
│   ├── evidence_capture.py      # End-of-session aggregation
│   ├── ai_drafter.py            # AI finding drafting
│   └── export_formatters.py     # Output to CSV/JSON/Markdown/DOCX
├── templates/
│   ├── findings-library/        # Reusable finding templates
│   └── report-templates/        # Word/PPTX report shells
└── docs/
    ├── ai-automation-workflow.md       # This document
    └── workflow-migration.md           # Ghostwriter-specific migration
```

Install and run:

```bash
# Clone repository
git clone <repo-url>
cd operator-toolkit

# Install dependencies
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt

# Configure API keys (1Password CLI)
export ANTHROPIC_API_KEY=$(op read "op://Security/Claude/api-key")

# Run end-of-session capture
python scripts/evidence_capture.py \
  --target "https://app.example.com" \
  --burp-project "~/burp/client.burp" \
  --screenshots "~/screenshots/client/"

# Draft findings
python scripts/ai_drafter.py \
  --evidence evidence.json \
  --templates templates/findings-library/ \
  --format markdown \
  --output findings/

# Import to your reporting tool (example: Cervantes CSV)
python scripts/export_formatters.py \
  --input findings/ \
  --format cervantes-csv \
  --output cervantes-import.csv
```

**Total setup time: <30 minutes** (assuming Python environment exists)

---

**Questions? Feedback?** Open an issue or contribute to the findings library.
