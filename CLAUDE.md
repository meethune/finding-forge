# CLAUDE.md — finding-forge

## Project Purpose

**finding-forge** is a tool-agnostic automation pipeline for penetration test reporting. It captures evidence from testing sessions (Burp Suite exports, screenshots, operator notes) and uses AI to draft complete findings from reusable templates.

The core value proposition: **operators spend time on analysis, not data entry.** Evidence capture and finding drafting are automated; the operator reviews and edits AI drafts rather than writing from scratch.

This project is intentionally decoupled from any specific reporting platform. Output formats (CSV, JSON, Markdown, DOCX) let operators import into whatever tool their team uses.

## Architecture

Four components connected by a structured evidence format (JSON):

```
Evidence Sources          Automation Layer              Output
─────────────────    ─────────────────────────    ──────────────
Burp Suite        →  burp/extract.py             
Screenshots       →  evidence/capture.py    →    models/schemas.py
Tool logs         →  drafting/drafter.py         
Operator notes    →  export/formatters.py   →    CSV / JSON / MD / DOCX
```

1. **Burp Extraction** (`finding_forge.burp`) — Reads Burp project files or proxy history exports, filters to target scope, extracts requests/responses and scanner findings.

2. **Evidence Capture** (`finding_forge.evidence`) — Aggregates Burp data, screenshots, tool logs, and conversational operator input into a structured evidence file.

3. **AI Drafting** (`finding_forge.drafting`) — Matches evidence to findings library templates, uses Claude to draft complete findings with CVSS scoring, impact, mitigation, and replication steps.

4. **Export** (`finding_forge.export`) — Formats drafted findings for import into reporting platforms (CSV, JSON, Markdown, DOCX).

## Data Flow

```
Operator runs pentest-capture
    → Burp data extracted + screenshots collected + operator describes session
    → Structured EngagementSession (JSON)

Operator runs pentest-draft
    → Evidence matched to template library
    → AI drafts finding (description, CVSS, impact, mitigation, steps, references)
    → Operator reviews/edits
    → Exported in target format
```

## CLI Commands

- `pentest-capture` — End-of-session evidence aggregation
- `pentest-draft` — AI-assisted finding drafting from captured evidence

## Development Conventions

- **Python >=3.12**, managed with `uv`
- **Formatting**: `ruff format` (black-compatible)
- **Linting**: `ruff check`
- **Type checking**: `mypy --strict`
- **Testing**: `pytest` with TDD — tests written before implementation
- **Data models**: Pydantic v2 for all structured data
- **AI integration**: Anthropic Python SDK (`anthropic`)
- **Secrets**: 1Password CLI (`op read`). Never hardcode API keys.
- **Commits**: Conventional Commits specification

## Findings Template Library

Templates live in `templates/findings/` as Markdown files. Each template must include:

- **title** — Dedup key (used for matching and import)
- **description** — Standard vulnerability description
- **severity** — Default CVSS vector string with justification
- **impact** — Business and technical impact
- **mitigation** — Remediation guidance
- **replication_steps** — Generic steps (customized per-engagement by AI)
- **references** — CWE, OWASP, and other authoritative sources
- **detection** — Host and network detection techniques

Templates are never modified in-place during an engagement. The AI clones a template and customizes the copy with engagement-specific evidence.

## Evidence Integrity Rules

- Never fabricate or modify evidence — Burp requests/responses extracted as-is
- Operator notes are conversational input, not AI-structured (prevents leading)
- Raw evidence files preserved alongside drafts for audit trail
- AI drafts clearly marked as AI-generated until operator reviews and accepts
