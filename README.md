# finding-forge

> Order from chaos. Provider-agnostic MCP server for pen test evidence capture and finding drafting.

## What is this?

An MCP server and CLI that captures evidence from penetration testing sessions and exposes tools, templates, and prompts for AI-assisted finding drafting. Works with **any MCP-capable AI client** (Claude Code, IBM watsonx, Gemini, etc.) and **any reporting platform** (Cervantes, Ghostwriter, Dradis, Plextrac, Word, Google Docs).

## Quickstart

### As an MCP server (recommended)

```bash
# Install
uv sync
```

Register the server globally so it's available from any directory. Use whichever MCP client your team runs:

**[IBM Bob](https://bob.ibm.com):**
```bash
bob mcp add --scope user finding-forge \
  uv run --project /path/to/finding-forge finding-forge-mcp
```

**Claude Code:**
```bash
claude mcp add --scope user finding-forge -- \
  uv run --project /path/to/finding-forge finding-forge-mcp
```

**Other MCP clients:** Add to your `.mcp.json` or equivalent config:

```json
{
  "mcpServers": {
    "finding-forge": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "/path/to/finding-forge", "finding-forge-mcp"]
    }
  }
}
```

Once registered, the AI client has access to tools for Burp extraction, nmap parsing, evidence capture, template matching, and finding export — plus two prompts:

- **`/forge`** — zero-input automation. The operator navigates to an artifacts directory and types `/forge`. The AI scans for Burp XML exports, nmap scan output, screenshots, and operator notes, then extracts evidence, matches templates, drafts findings, validates, and exports — all without manual tool chaining.
- **`/draft_finding`** — focused single-finding drafting from an evidence summary and optional template name.

### Custom templates directory

By default the server uses bundled templates packaged inside the wheel. To point at your own templates, set the `FINDING_FORGE_TEMPLATES_DIR` environment variable when registering:

```bash
# IBM Bob
bob mcp add --scope user finding-forge \
  FINDING_FORGE_TEMPLATES_DIR=/path/to/my/templates \
  uv run --project /path/to/finding-forge finding-forge-mcp

# Claude Code
claude mcp add --scope user finding-forge \
  --env FINDING_FORGE_TEMPLATES_DIR=/path/to/my/templates -- \
  uv run --project /path/to/finding-forge finding-forge-mcp
```

### As a CLI

```bash
# Capture evidence from a testing session
uv run finding-forge capture --target https://app.example.com --engagement ENG-2025-042 --burp-xml burp_export.xml --output evidence.json

# Export a finding
uv run finding-forge export --finding finding.json --format markdown
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `extract_burp` | Parse Burp Suite XML export, filter to target scope |
| `extract_nmap` | Parse nmap XML output, filter to target scope |
| `capture_evidence` | Create an engagement session with evidence |
| `list_finding_templates` | List all available finding templates |
| `get_finding_template` | Get a specific template by name |
| `match_finding_templates` | Find templates matching a query |
| `export_finding` | Format a finding as JSON/CSV/Markdown/Cervantes CSV |
| `calculate_cvss` | Compute CVSS 3.1 score from 8 individual base metrics |
| `validate_finding` | Validate a Finding JSON object against the schema |

## Development

```bash
uv sync
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/
uv run pytest
```

## Architecture

```
Core Library (pure Python)          Wrappers
──────────────────────────────    ─────────────────
models/schemas.py                 server.py (MCP)
burp/extract.py                   cli.py (Click)
nmap/extract.py
evidence/capture.py
export/formatters.py
templates/library.py
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture and conventions.

## Export Formats

| Format | Description |
|--------|-------------|
| `json` | Full finding as JSON |
| `csv` | Flat key-value dict as JSON (for generic CSV pipelines) |
| `markdown` | Formatted Markdown for Word/Google Docs |
| `cervantes` | Semicolon-delimited CSV for Cervantes bulk import |

> **Cervantes caveat:** Cervantes' CSV import is unreliable — parsing can fail silently or reject valid rows depending on version and database state. The `cervantes` format is provided as a convenience but YMMV. Always verify imported findings in Cervantes after upload.
