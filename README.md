# finding-forge

> Order from chaos. Tool-agnostic pen test evidence capture and AI-assisted finding drafting.

**Status: scaffold — not yet functional**

## What is this?

An automation pipeline that captures evidence from penetration testing sessions and uses AI to draft complete findings from reusable templates. Works with any reporting platform — Cervantes, Ghostwriter, Dradis, Plextrac, Word, or Google Docs.

## Quickstart

```bash
# Install
uv sync

# Check CLI
uv run pentest-capture --help
uv run pentest-draft --help
```

## Development

```bash
# Install with dev dependencies
uv sync

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check
uv run mypy src/

# Test
uv run pytest
```

## Architecture

```
Evidence Sources → Burp Extraction → Evidence Capture → AI Drafting → Export
                                                                    ↓
                                                          CSV / JSON / MD / DOCX
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture and conventions.
