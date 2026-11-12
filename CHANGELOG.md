# Changelog

## 1.1.3 (2026-11-12)

### Security

- Require MCP `>=1.30.0,<2`, retaining the 1.x API and locking MCP to 1.30.0.
- Refresh production and development dependencies to address known advisories
  in AnyIO, certifi, cryptography, MCP, pydantic-settings, PyJWT,
  python-multipart, and Starlette.

### Documentation

- Document dependency audits, lockfile and environment checks, and package builds.

## 1.1.2 (2026-06-04)

### Added

- `extract_nmap` MCP tool — parses nmap XML output via `python-libnmap`, returns per-service results with host, port, protocol, state, service name, version banner, OS match, and NSE script output, filtered to target scope
- `NmapService` and `NmapScriptResult` Pydantic models for structured nmap data
- `python-libnmap>=0.7` dependency (uses `defusedxml` internally)

### Security

- **Workspace path confinement** — `extract_burp` and `extract_nmap` now resolve caller-supplied paths and reject anything outside the workspace root via `Path.relative_to()`. Workspace root is read from `FINDING_FORGE_WORKSPACE` env var, falling back to CWD. Prevents arbitrary filesystem reads by a malicious or misconfigured MCP client.

### Fixed

- `validate_finding` exception handler narrowed from bare `except Exception` to `except pydantic.ValidationError` — internal server errors now propagate as `ToolError` instead of being silently returned as validation messages
- CVSS accessor calls (`c.scores()`, `c.severities()`) moved inside the `try` block; empty-list result now raises a clean `ValueError` instead of an unguarded `IndexError`
- `type: ignore` suppressions removed from `load_template` — `cwe_ids` and `tags` YAML fields are now coerced via explicit `isinstance(raw, list)` guards, defending against bare-string YAML values
- `scripts/import_templates.py` no longer hard-codes a checkout-relative CSV path; accepts the CSV path as `sys.argv[1]`

### Tests

- 258 tests (245 → 258); overall coverage 96% → 98%
- `cli.py` brought to 100% coverage — `--burp-xml` ingestion branch now exercised
- `server.py` coverage 93% → 97% — `template_resource` return path and `draft_finding` `FileNotFoundError` branch now covered
- New workspace boundary tests: `TestResolveWorkspacePath` (5), `TestExtractBurpToolWorkspaceBoundary` (2), `TestExtractNmapToolWorkspaceBoundary` (1), `TestValidateFindingToolErrorHandling` (2)

## 1.1.1 (2026-06-03)

### Security

- **Path traversal prevention** — `get_template` validates template names against directory escape via path separators and `is_relative_to` containment check
- **XML entity expansion blocked** — replaced `xml.etree.ElementTree` with `defusedxml.ElementTree` in Burp XML parser; added `defusedxml>=0.7` dependency
- **CSV formula injection sanitized** — `_escape_cervantes` prefixes formula trigger characters (`=`, `+`, `-`, `@`, tab, CR) with single quote; CVSS vector field now goes through escaping
- **Severity rating validation** — `FindingSeverity.rating` normalizes case (`"critical"` → `"Critical"`, `"info"` → `"Informational"`) and rejects unknown values

### Fixed

- Corrupt base64 in Burp XML no longer crashes the entire parser — falls back to raw text
- Non-numeric `<status>` values in Burp XML handled gracefully (defaults to 0)
- Single malformed template file no longer prevents loading all templates — skipped with warning
- Empty YAML frontmatter raises clear `ValueError` instead of `AttributeError`
- HTTP response reason phrase uses `http.HTTPStatus` instead of hardcoded `"OK"` (e.g., 404 now renders `"Not Found"`)
- Version string in `__init__.py` corrected from `1.0.0` to `1.1.0`
- Bundled templates packaged inside the wheel via `importlib.resources` — resolves correctly in editable installs, wheels, and zipapps (#1)
- `scripts/import_templates.py` output path updated to `src/finding_forge/templates/findings/`
- Template path warning logged when bundled directory is missing and no override is set

### Added

- `finding-forge` CLI entry point exposing full Click group (capture + export + --version)
- 35 new tests (184 → 219) covering all security, robustness, and packaging fixes
- Shared test fixtures consolidated in `conftest.py`

### Removed

- `pentest-capture` CLI entry point — use `finding-forge capture` instead

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
