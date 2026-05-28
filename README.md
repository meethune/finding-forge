# finding-forge

> Order from chaos. Provider-agnostic MCP server for pen test evidence capture and finding drafting.

## What is this?

An MCP server and CLI that captures evidence from penetration testing sessions and exposes tools, templates, and prompts for AI-assisted finding drafting. Works with **any MCP-capable AI client** (Claude Code, IBM watsonx, Gemini, etc.) and **any reporting platform** (Cervantes, Ghostwriter, Dradis, Plextrac, Word, Google Docs).

## Quickstart

### As an MCP server (recommended)

```bash
# Install
uv sync

# Register globally — available from any directory
claude mcp add --scope user finding-forge -- \
  uv run --project /path/to/finding-forge finding-forge-mcp

# Or project-scoped only (the .mcp.json auto-configures when you're in this directory)
```

Once registered, the AI client has access to tools for Burp extraction, evidence capture, template matching, and finding export — plus a `draft_finding` prompt for AI-assisted drafting.

### Custom templates directory

By default the server uses the bundled `templates/findings/` directory. To point at your own templates:

```bash
# Via environment variable
claude mcp add --scope user finding-forge \
  --env FINDING_FORGE_TEMPLATES_DIR=/path/to/my/templates -- \
  uv run --project /path/to/finding-forge finding-forge-mcp
```

### As a CLI

```bash
# Capture evidence from a testing session
uv run pentest-capture --target https://app.example.com --engagement ENG-2025-042 --burp-xml burp_export.xml --output evidence.json

# Export a finding
uv run finding-forge export --finding finding.json --format markdown
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `extract_burp` | Parse Burp Suite XML export, filter to target scope |
| `capture_evidence` | Create an engagement session with evidence |
| `list_finding_templates` | List all available finding templates |
| `get_finding_template` | Get a specific template by name |
| `match_finding_templates` | Find templates matching a query |
| `export_finding` | Format a finding as JSON/CSV/Markdown |

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
evidence/capture.py
export/formatters.py
templates/library.py
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture and conventions.
