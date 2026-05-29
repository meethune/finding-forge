# Finding Schema Reference

The `export_finding` MCP tool expects a JSON object matching the `Finding` Pydantic model.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Finding title, specific to the engagement |
| `description` | string | Technical description of the vulnerability |
| `severity` | object | CVSS scoring (see below) |
| `impact` | string | Business and technical impact |
| `mitigation` | string | Remediation steps |
| `replication_steps` | string | Step-by-step reproduction from evidence |

## Severity Object

| Field | Type | Description |
|-------|------|-------------|
| `rating` | string | Critical, High, Medium, Low, or Informational |
| `cvss_vector` | string (optional) | CVSS 3.1 vector string — use `calculate_cvss` tool |
| `cvss_score` | number (optional) | Auto-computed from vector if omitted |
| `justification` | string (optional) | 1-sentence severity justification |

## Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `references` | list[string] | [] | URLs to CWE, OWASP, etc. |
| `detection` | string | "" | How to detect the vulnerability |
| `cwe_ids` | list[string] | [] | CWE identifiers (e.g., "CWE-89") |
| `evidence` | list[object] | [] | Evidence items (title + evidence_type) |

## Field Aliases

The model accepts common alternative names:

| You can write | Maps to |
|---------------|---------|
| `remediation` | `mitigation` |
| `steps`, `poc`, `reproduction_steps` | `replication_steps` |
| `risk` | `severity` (as string → `{"rating": value}`) |
| `cwe`, `cwes` | `cwe_ids` |

## Export Formats

Pass the JSON to `export_finding` with one of:

| Format | Description |
|--------|-------------|
| `json` | Full finding as JSON |
| `csv` | Flat key-value dict |
| `markdown` / `md` | Formatted Markdown |
| `cervantes` / `cervantes-csv` | Semicolon-delimited CSV for Cervantes import |
