---
name: draft-finding
description: Draft a concise, evidence-anchored penetration test finding with deterministic CVSS scoring. Use when drafting security findings, vulnerability reports, or pentest results. Requires the finding-forge MCP server.
compatibility: Requires finding-forge MCP server and Python 3.12+
metadata:
  author: finding-forge
  version: "1.0"
---

# Draft Finding

You are drafting a security finding for a penetration test report. Follow this workflow exactly.

## Workflow

1. **Match a template** — call `match_finding_templates` with keywords from the evidence. Pick the best-fit template.
2. **Review the template** — call `get_finding_template` to read the full template. Note the severity baseline and references.
3. **Calculate CVSS** — call `calculate_cvss` with the 8 base metrics based on the evidence. Answer each metric honestly:
   - Attack Vector: Is this network-accessible (N), adjacent (A), local (L), or physical (P)?
   - Attack Complexity: Any special conditions needed (H) or straightforward (L)?
   - Privileges Required: None (N), low (L), or high (H)?
   - User Interaction: Does the victim need to do something (R) or not (N)?
   - Scope: Does exploitation impact resources beyond the vulnerable component (C) or not (U)?
   - Confidentiality/Integrity/Availability: What is impacted and how much (N/L/H)?
4. **Draft the finding** — write the finding JSON (schema below).
5. **Export** — call `export_finding` with the JSON and the desired format.

## Requirements

- **MUST** include the CVSS vector and score from `calculate_cvss` — never hand-compute or estimate scores
- **MUST** anchor every claim to provided evidence (Burp requests, screenshots, operator notes)
- **MUST** be concise:
  - Description: 2-4 sentences
  - Impact: 2-3 sentences
  - Mitigation: bullet points, no sample code unless evidence references source code
  - Replication Steps: from the evidence, not generic
  - Detection: 1-2 sentences
- **MUST NOT** fabricate requests, responses, endpoints, or file paths not in the evidence
- **MUST NOT** include sample code, full implementations, or extended tutorials
- **MUST NOT** expand template content — use it for severity baseline and references only
- **MUST** adjust severity from the template baseline based on actual engagement context

## Finding JSON Schema

Output the finding as a JSON object matching this schema:

```json
{
  "title": "string (required) — specific to this engagement",
  "description": "string (required) — 2-4 sentences",
  "severity": {
    "rating": "string — Critical/High/Medium/Low/Informational",
    "cvss_vector": "string — from calculate_cvss tool",
    "cvss_score": "number — from calculate_cvss tool",
    "justification": "string — 1 sentence explaining the rating"
  },
  "impact": "string (required) — 2-3 sentences",
  "mitigation": "string (required) — bullet points",
  "replication_steps": "string (required) — from evidence",
  "references": ["array of URL strings"],
  "detection": "string — 1-2 sentences",
  "cwe_ids": ["array of CWE-XX strings"]
}
```

See [finding-schema.md](references/finding-schema.md) for the full Pydantic model reference.

## Example

Given operator notes mentioning SQL injection in a login form:

1. `match_finding_templates("sql injection")` → picks `cwe-89`
2. `get_finding_template("cwe-89")` → reads template
3. `calculate_cvss(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N")` → `{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 9.1, "rating": "Critical"}`
4. Draft the finding JSON using the evidence and CVSS result
5. `export_finding(finding_json, "cervantes")` or `"markdown"`
