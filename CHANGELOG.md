# Changelog

## 1.1.0 (2026-06-03)

### Added

- **`forge` MCP prompt** — zero-input finding generation. Operator navigates to an artifacts directory, invokes `/forge`, and gets finished findings. The AI scans for Burp XML, screenshots, and operator notes, then extracts evidence, matches templates, calculates CVSS, drafts, validates, and exports autonomously.
- **Comprehensive server instructions** — replaces 2-sentence instructions with full workflow documentation covering tool chaining, prompt descriptions, and evidence integrity rules. Any MCP client now understands how to use the tools together.
- **Evidence in markdown export** — `export_finding` renders full evidence sections with operator notes, `![title](path)` screenshot image links, and ```` ```http ```` request/response code blocks.
- **Evidence in CSV export** — `export_csv_row` includes a JSON-serialized `evidence` column preserving full evidence structure.
- **Full evidence schema in `export_finding` and `draft_finding`** — tool docstrings and prompt output schema now document all evidence fields (screenshots, operator_notes, requests with headers/body/status).

### Fixed

- Evidence section renders after Replication Steps (was at the end after References/Detection)
- Severity metadata lines use hard line breaks so they render on separate lines
- Screenshot paths adjusted for `findings/` subdirectory output (prefix `../`)
- Forge prompt enforces `export_finding` verbatim output — prevents AI from constructing markdown that drops evidence
- Forge prompt requires inline code backticks for payloads, HTML tags, and URLs containing code
- HTTP request/response blocks use ```` ```http ```` fencing with full request line, headers, and body
- Screenshots use evidence title as alt text instead of filename

## 1.0.0 (2026-06-01)

Initial release. Provider-agnostic MCP server for penetration test reporting automation.

### MCP Server

- **8 tools**: `extract_burp`, `capture_evidence`, `list_finding_templates`, `get_finding_template`, `match_finding_templates`, `export_finding`, `calculate_cvss`, `validate_finding`
- **1 resource template**: `templates://findings/{name}`
- **2 prompts**: `forge` (zero-input full-pipeline automation), `draft_finding` (single-finding drafting)

### Template Library

- 78 finding templates covering OWASP Top 10:2025, OWASP LLM Top 10:2025, and CWE Top 25:2025
- Imported from sibling `template-generator` project
- Markdown + YAML frontmatter format with tag-based matching

### Export Formats

- JSON, CSV, Markdown, Cervantes CSV
- Format aliases: `md`, `cervantes-csv`, `cervantes_csv`

### Core Features

- Burp Suite XML proxy history parsing with early scope filtering
- Evidence capture with session serialization (JSON)
- CVSS 3.1 calculator (RedHat `cvss` library) — deterministic scoring from 8 base metrics
- Auto-compute CVSS score from vector on all entry points (Pydantic validator)
- Input coercion: field aliases (`remediation`→`mitigation`, `type`→`evidence_type`), severity string→object
- Finding schema validation tool for pre-export checks

### CLI

- `pentest-capture` — evidence aggregation with Burp XML support
- `finding-forge export` — export findings in any supported format

### Architecture

- Pure Python core library with no AI/MCP dependency
- Two thin wrappers: MCP server (`server.py`) + Click CLI (`cli.py`)
- `_FindingBase` shared model for `Finding` and `FindingTemplate`
- Provider-agnostic: works with Claude Code, IBM Bob, Gemini, or any MCP client

### Demo

- Sample engagement (`demo/`) with Burp export, operator notes, screenshot, and walkthrough script
