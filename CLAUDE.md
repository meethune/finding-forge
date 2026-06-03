# CLAUDE.md — finding-forge

## Project Purpose

**finding-forge** is a provider-agnostic MCP server and CLI for penetration test reporting automation. It captures evidence from testing sessions (Burp Suite exports, screenshots, operator notes) and exposes tools, templates, and prompts that any MCP-capable AI client can use to draft complete findings.

The core value proposition: **operators spend time on analysis, not data entry.** Evidence capture is automated; finding drafting happens in whatever AI client the team uses (Claude Code, IBM watsonx, Gemini, etc.).

This project is intentionally decoupled from any specific AI provider or reporting platform. Output formats (CSV, JSON, Markdown) let operators import into whatever tool their team uses.

## Architecture

Core library (pure Python, no AI/MCP dependency) with two thin wrappers:

```
Core Library                          Wrappers
──────────────────────────────    ─────────────────────────
models/schemas.py (Pydantic)      server.py  (MCP server)
burp/extract.py                   cli.py     (Click CLI)
evidence/capture.py
export/formatters.py
templates/library.py
```

1. **Burp Extraction** (`finding_forge.burp`) — Parses Burp Suite proxy history XML exports, filters to target scope, extracts requests/responses.

2. **Evidence Capture** (`finding_forge.evidence`) — Aggregates Burp data, screenshots, and operator notes into a structured EngagementSession (JSON).

3. **Template Library** (`finding_forge.templates`) — Loads, lists, and matches finding templates from bundled Markdown files with YAML frontmatter. Templates are packaged inside the wheel at `finding_forge/templates/findings/` and resolved via `importlib.resources`. Custom template directories can override via `FINDING_FORGE_TEMPLATES_DIR` env var or `create_server(templates_dir=...)`.

4. **Export** (`finding_forge.export`) — Formats drafted findings for import into reporting platforms (CSV, JSON, Markdown, Cervantes CSV).

> **Note on Cervantes export:** Cervantes' CSV import functionality is unreliable — parsing can fail silently or reject valid rows depending on version and database state. The `cervantes` export format is provided as a convenience but results may vary. Always verify imported findings in Cervantes after upload.

5. **MCP Server** (`finding_forge.server`) — Exposes all of the above as MCP tools, resources, and prompts. The `draft_finding` prompt replaces direct AI integration — the client's model executes the drafting.

## MCP Tools

- `extract_burp` — Parse Burp XML export, filter to target scope
- `capture_evidence` — Create an engagement session with evidence
- `list_finding_templates` — List all available templates
- `get_finding_template` — Get a specific template by name
- `match_finding_templates` — Find templates matching a query
- `export_finding` — Format a finding as JSON/CSV/Markdown/Cervantes CSV
- `calculate_cvss` — Compute CVSS 3.1 score from 8 base metrics
- `validate_finding` — Validate a Finding JSON object against the schema

## MCP Resources

- `templates://findings/{name}` — Read-only access to individual templates

## MCP Prompts

- `forge` — Zero-input automation: scans the operator's artifacts directory for Burp XML exports, screenshots, and operator notes, then extracts evidence, identifies findings, matches templates, drafts, validates, and exports. The operator types `/forge` and gets finished findings.
- `draft_finding` — Focused single-finding drafting from an evidence summary and optional template name

## CLI Commands

- `finding-forge capture` — End-of-session evidence aggregation
- `finding-forge export` — Export a finding in any supported format
- `finding-forge-mcp` — Start the MCP server

## Development Conventions

- **Input coercion**: `Finding` and `Evidence` have Pydantic `model_validator(mode="before")` that normalize field aliases (e.g., `remediation`→`mitigation`, `type`→`evidence_type`) and coerce `severity` from string to `{"rating": string}`. This runs on all entry points (MCP, CLI, direct construction).
- **CVSS auto-compute**: `FindingSeverity` has a `model_validator(mode="after")` that computes `cvss_score` from `cvss_vector` when vector is present but score is missing. Uses the `cvss` library (RedHat).
- **Export format aliases**: `export_finding` accepts aliases (`md`→`markdown`, `cervantes-csv`→`cervantes`) via `_FORMAT_DISPATCH` dict in `formatters.py`.
- **Model inheritance**: `Finding` and `FindingTemplate` share a `_FindingBase` with 9 common fields. `Finding` adds `evidence`; `FindingTemplate` adds `name`, `tags`, `finding_type`, `guidance`.
- **Python >=3.12**, managed with `uv`
- **Formatting**: `ruff format` (black-compatible)
- **Linting**: `ruff check`
- **Type checking**: `mypy --strict`
- **Testing**: `pytest` with TDD — tests written before implementation
- **Data models**: Pydantic v2 for all structured data
- **MCP server**: Official `mcp` Python SDK (FastMCP)
- **Secrets**: 1Password CLI (`op read`). Never hardcode API keys.
- **Commits**: Conventional Commits specification

## Findings Template Library

- 78 templates covering OWASP Top 10:2025, OWASP LLM Top 10:2025, and CWE Top 25:2025
- Imported from sibling `template-generator` project via `scripts/import_templates.py`

Templates live in `src/finding_forge/templates/findings/` as Markdown files with YAML frontmatter (packaged inside the wheel via `importlib.resources`). Each template must include:

- **title** — Dedup key (used for matching and import)
- **description** — Standard vulnerability description
- **severity** — Default CVSS vector string with justification
- **impact** — Business and technical impact
- **mitigation** — Remediation guidance
- **replication_steps** — Generic steps (customized per-engagement by AI)
- **references** — CWE, OWASP, and other authoritative sources
- **detection** — Host and network detection techniques
- **tags** — Keywords for template matching (e.g., `sqli`, `injection`, `owasp-a03`)
- **cwe_ids** — CWE identifiers for matching

Templates are never modified in-place during an engagement. The AI clones a template and customizes the copy with engagement-specific evidence.

## Evidence Integrity Rules

- Never fabricate or modify evidence — Burp requests/responses extracted as-is
- Operator notes are conversational input, not AI-structured (prevents leading)
- Raw evidence files preserved alongside drafts for audit trail
- AI drafts clearly marked as AI-generated until operator reviews and accepts
