"""MCP server for finding-forge — pentest evidence capture and finding drafting."""

import json
import os
from collections.abc import Sequence
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import Message, UserMessage
from pydantic import BaseModel

from finding_forge.burp.extract import extract_burp_data
from finding_forge.cvss.calculator import (
    calculate_cvss as _calculate_cvss,
)
from finding_forge.evidence.capture import add_evidence, create_session
from finding_forge.export.formatters import export_finding as _export_finding
from finding_forge.models.schemas import Finding
from finding_forge.templates.library import (
    get_template,
    list_templates,
    match_templates,
)


def _dump_models(models: Sequence[BaseModel]) -> str:
    return json.dumps([m.model_dump(mode="json") for m in models], indent=2)


_BUNDLED_TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "templates" / "findings"
)


def _resolve_templates_dir(override: Path | None = None) -> Path:
    if override:
        return override
    env_val = os.environ.get("FINDING_FORGE_TEMPLATES_DIR")
    if env_val:
        return Path(env_val)
    return _BUNDLED_TEMPLATES_DIR


def create_server(templates_dir: Path | None = None) -> FastMCP:
    """Create and configure the MCP server instance."""
    resolved_dir = _resolve_templates_dir(templates_dir)

    server = FastMCP(
        "finding-forge",
        instructions=(
            "Pentest finding generation from engagement artifacts. "
            "Operators capture evidence during testing (Burp Suite "
            "exports, screenshots, notes) and use these tools to "
            "produce complete security findings.\n\n"
            "## Tool Workflow\n\n"
            "Tools chain together in this sequence:\n"
            "1. `extract_burp` — parse Burp XML, filter to target "
            "scope, returns structured HTTP request/response pairs\n"
            "2. `match_finding_templates` — search 78 templates by "
            "vulnerability type, returns ranked matches with severity "
            "baselines, mitigation guidance, and references\n"
            "3. `calculate_cvss` — compute CVSS 3.1 score from 8 "
            "base metrics, returns vector string and numeric score\n"
            "4. Draft the finding as JSON — combine evidence, "
            "template baseline, and CVSS into the Finding schema\n"
            "5. `validate_finding` — check the JSON against the "
            "Finding schema, returns errors to fix\n"
            "6. `export_finding` — render as markdown, CSV, JSON, "
            "or Cervantes format for reporting platforms\n\n"
            "## Prompts\n\n"
            "- `forge` — zero-input automation: scans the operator's "
            "artifacts directory, extracts evidence, identifies "
            "findings, matches templates, drafts, validates, and "
            "exports. The operator types /forge and gets finished "
            "findings.\n"
            "- `draft_finding` — focused single-finding drafting "
            "from an evidence summary and optional template name.\n\n"
            "## Evidence Integrity\n\n"
            "- Evidence anchors all claims — never fabricate HTTP "
            "requests, responses, endpoints, or screenshots\n"
            "- CVSS scores must be computed via `calculate_cvss`, "
            "never estimated\n"
            "- Templates provide severity baselines and references, "
            "not content to expand\n"
            "- Operator notes are authoritative context"
        ),
    )

    @server.tool()
    def extract_burp(xml_path: str, target_hosts: list[str]) -> str:
        """Parse Burp XML export, filter to target scope."""
        results = extract_burp_data(Path(xml_path), target_hosts)
        return _dump_models(results)

    @server.tool()
    def capture_evidence(
        engagement_id: str,
        target: str,
        title: str,
        evidence_type: str,
        operator_notes: str = "",
        operator: str = "",
    ) -> str:
        """Create an engagement session with a single evidence item."""
        session = create_session(
            engagement_id=engagement_id,
            target=target,
            operator=operator,
        )
        session = add_evidence(
            session,
            title=title,
            evidence_type=evidence_type,
            operator_notes=operator_notes,
        )
        return session.model_dump_json(indent=2)

    @server.tool()
    def list_finding_templates() -> str:
        """List all available finding templates with metadata."""
        templates = list_templates(resolved_dir)
        return _dump_models(templates)

    @server.tool()
    def get_finding_template(name: str) -> str:
        """Get a specific finding template by name."""
        tmpl = get_template(resolved_dir, name)
        return tmpl.model_dump_json(indent=2)

    @server.tool()
    def match_finding_templates(query: str, max_results: int = 5) -> str:
        """Find templates matching a text query by tags, title, and CWE IDs."""
        results = match_templates(resolved_dir, query, max_results)
        return _dump_models(results)

    @server.tool()
    def export_finding(finding_json: str, fmt: str) -> str:
        """Export a Finding as JSON, CSV, Markdown, or Cervantes CSV.

        finding_json must be a JSON object with these fields:
          title (str, required)
          description (str, required)
          severity (object: {rating, cvss_vector?, cvss_score?})
          impact (str, required)
          mitigation (str, required)
          replication_steps (str, required)
          references (list[str], optional)
          detection (str, optional)
          cwe_ids (list[str], optional)
          evidence (list[object], optional) — each object:
            title (str)
            evidence_type (str)
            operator_notes (str, optional)
            screenshots (list[str], optional) — file paths or URLs
            scanner_findings (list[str], optional)
            requests (list[object], optional) — each object:
              url, method, host, path, request_headers (dict),
              request_body (str?), status_code (int),
              response_headers (dict), response_body (str?)

        fmt: "json", "csv", "markdown", or "cervantes"
        """
        finding = Finding.model_validate_json(finding_json)
        return _export_finding(finding, fmt)

    @server.tool()
    def calculate_cvss(
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
    ) -> str:
        """Calculate CVSS 3.1 score from individual metrics.

        Each parameter accepts standard CVSS abbreviations:
          attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
          attack_complexity: L (Low), H (High)
          privileges_required: N (None), L (Low), H (High)
          user_interaction: N (None), R (Required)
          scope: U (Unchanged), C (Changed)
          confidentiality: N (None), L (Low), H (High)
          integrity: N (None), L (Low), H (High)
          availability: N (None), L (Low), H (High)

        Returns JSON with vector, score, and rating.
        """
        result = _calculate_cvss(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
        return result.model_dump_json(indent=2)

    @server.tool()
    def validate_finding(finding_json: str) -> str:
        """Validate a Finding JSON object against the schema.

        Returns "valid" if the finding passes validation,
        or a list of specific errors to fix.
        """
        try:
            Finding.model_validate_json(finding_json)
        except Exception as e:
            return f"Validation errors:\n{e}"
        return "valid"

    @server.resource("templates://findings/{name}")
    def template_resource(name: str) -> str:
        """Read a specific finding template as a resource."""
        tmpl = get_template(resolved_dir, name)
        return tmpl.model_dump_json(indent=2)

    @server.prompt()
    def draft_finding(
        evidence_summary: str,
        template_name: str = "",
    ) -> list[Message]:
        """Generate a prompt for drafting a complete security finding from evidence."""
        template_context = ""
        if template_name:
            try:
                tmpl = get_template(resolved_dir, template_name)
                refs = ", ".join(tmpl.references)
                cwes = ", ".join(tmpl.cwe_ids)
                template_context = (
                    f"\n\n## Reference Template: {tmpl.title}\n\n"
                    f"**Severity baseline:** {tmpl.severity.rating}\n"
                    f"**Mitigation guidance:** {tmpl.mitigation}\n"
                    f"**References:** {refs}\n"
                    f"**CWE:** {cwes}\n"
                )
                if tmpl.guidance:
                    template_context += f"**Guidance:** {tmpl.guidance}\n"
            except FileNotFoundError:
                template_context = (
                    f"\n\nTemplate '{template_name}' not found. "
                    "Draft the finding without a template reference."
                )

        return [
            UserMessage(
                content=(
                    "You are a penetration test report writer. "
                    "Draft a concise security finding from the "
                    "evidence below.\n\n"
                    "## Output format\n\n"
                    "Output a single JSON code block matching this "
                    "schema:\n\n"
                    "```json\n"
                    "{\n"
                    '  "title": "string",\n'
                    '  "description": "2-4 sentences",\n'
                    '  "severity": {\n'
                    '    "rating": "Critical|High|Medium|Low",\n'
                    '    "cvss_vector": "CVSS:3.1/...",\n'
                    '    "cvss_score": 0.0,\n'
                    '    "justification": "1 sentence"\n'
                    "  },\n"
                    '  "impact": "2-3 sentences",\n'
                    '  "mitigation": "bullet points",\n'
                    '  "replication_steps": "from evidence",\n'
                    '  "references": ["urls"],\n'
                    '  "detection": "1-2 sentences",\n'
                    '  "cwe_ids": ["CWE-XX"],\n'
                    '  "evidence": [\n'
                    "    {\n"
                    '      "title": "string",\n'
                    '      "evidence_type": "screenshot|http_request|other",\n'
                    '      "operator_notes": "string",\n'
                    '      "screenshots": ["file paths or URLs"],\n'
                    '      "requests": [\n'
                    "        {\n"
                    '          "url": "string",\n'
                    '          "method": "GET|POST|...",\n'
                    '          "host": "string",\n'
                    '          "path": "string",\n'
                    '          "request_headers": {},\n'
                    '          "request_body": "string or null",\n'
                    '          "status_code": 200,\n'
                    '          "response_headers": {},\n'
                    '          "response_body": "string or null"\n'
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "  ]\n"
                    "}\n"
                    "```\n\n"
                    "Use the `calculate_cvss` tool to get the "
                    "vector and score — do not estimate.\n\n"
                    "## Rules\n\n"
                    "- Output ONLY the JSON block. No preamble, "
                    "no commentary.\n"
                    "- Evidence is the anchor — every claim must "
                    "trace to provided evidence.\n"
                    "- Never fabricate requests, responses, or "
                    "endpoints not in the evidence.\n"
                    "- No sample code unless evidence references "
                    "source code.\n"
                    "- Use the template for severity baseline and "
                    "references, not as content to expand.\n"
                    "- Adjust severity from the template baseline "
                    "based on actual engagement context.\n\n"
                    f"## Evidence\n\n{evidence_summary}"
                    f"{template_context}"
                ),
            ),
        ]

    @server.prompt()
    def forge() -> list[Message]:
        """Scan artifacts directory and generate complete findings."""
        return [
            UserMessage(
                content=(
                    "You are a penetration test report automation "
                    "system. Your job is to scan the operator's "
                    "current working directory for engagement "
                    "artifacts, extract evidence, and produce "
                    "complete security findings with zero manual "
                    "input.\n\n"
                    "## Phase 1 — Discover Artifacts\n\n"
                    "Scan the current working directory for:\n"
                    "- `.xml` files — validate as Burp Suite exports "
                    "by checking for `<items burpVersion=` in the "
                    "first few lines\n"
                    "- `.png`, `.jpg`, `.jpeg` files — screenshots "
                    "(search subdirectories too)\n"
                    "- `.md`, `.txt` files (excluding README files) "
                    "— operator notes\n"
                    "- `evidence.json` — pre-captured engagement "
                    "sessions\n\n"
                    "Infer the target host(s) by reading Burp XML "
                    "host fields — use the most common in-scope "
                    "host. Derive the engagement ID from the "
                    "directory name.\n\n"
                    "## Phase 2 — Extract and Analyze\n\n"
                    "1. Call `extract_burp` for each Burp XML file "
                    "with the inferred target host(s).\n"
                    "2. Read all operator notes files — these are "
                    "the primary source of truth. Operator notes "
                    "contain severity assessments, business context, "
                    "scope constraints, and chained impact analysis "
                    "that Burp data alone cannot provide.\n"
                    "3. Identify distinct vulnerability findings "
                    "from the combined evidence. Each finding "
                    "should map to a specific vulnerability with "
                    "supporting Burp requests, screenshots, and "
                    "operator observations.\n\n"
                    "## Phase 3 — Generate Findings\n\n"
                    "For each identified finding:\n\n"
                    "1. Call `match_finding_templates` with a "
                    "descriptive query for the vulnerability type. "
                    "Select the best-matching template as a "
                    "baseline.\n"
                    "2. Reason through each of the 8 CVSS 3.1 base "
                    "metrics (attack_vector, attack_complexity, "
                    "privileges_required, user_interaction, scope, "
                    "confidentiality, integrity, availability) based "
                    "on the evidence. Then call `calculate_cvss` "
                    "with those values.\n"
                    "3. Draft the finding as a JSON object:\n"
                    "```json\n"
                    "{\n"
                    '  "title": "string",\n'
                    '  "description": "2-4 sentences",\n'
                    '  "severity": {\n'
                    '    "rating": "Critical|High|Medium|Low",\n'
                    '    "cvss_vector": "from calculate_cvss",\n'
                    '    "cvss_score": 0.0,\n'
                    '    "justification": "1 sentence"\n'
                    "  },\n"
                    '  "impact": "2-3 sentences",\n'
                    '  "mitigation": "from template + context",\n'
                    '  "replication_steps": "from evidence",\n'
                    '  "references": ["from template"],\n'
                    '  "detection": "1-2 sentences",\n'
                    '  "cwe_ids": ["from template"],\n'
                    '  "evidence": [\n'
                    "    {\n"
                    '      "title": "string",\n'
                    '      "evidence_type": "string",\n'
                    '      "operator_notes": "string",\n'
                    '      "screenshots": ["paths — use '
                    '![title](path) syntax in markdown"],\n'
                    '      "requests": [\n'
                    "        {\n"
                    '          "url": "string",\n'
                    '          "method": "string",\n'
                    '          "host": "string",\n'
                    '          "path": "string",\n'
                    '          "request_headers": {},\n'
                    '          "request_body": "string or null",\n'
                    '          "status_code": 200,\n'
                    '          "response_headers": {},\n'
                    '          "response_body": "string or null"\n'
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "  ]\n"
                    "}\n"
                    "```\n"
                    "4. Call `validate_finding` with the drafted "
                    "JSON. If validation fails, fix the errors and "
                    "re-validate.\n"
                    "5. Call `export_finding` with `fmt=markdown` to "
                    "render the final output.\n"
                    "6. Write the markdown to "
                    "`findings/<slugified-title>.md` and the JSON to "
                    "`findings/<slugified-title>.json`. Create the "
                    "`findings/` directory if it does not exist.\n\n"
                    "**Important:** Since output files are written to "
                    "the `findings/` subdirectory, adjust any relative "
                    "screenshot paths in the evidence to be relative "
                    "to that directory (e.g., `screenshots/proof.png` "
                    "becomes `../screenshots/proof.png`).\n\n"
                    "## Phase 4 — Summary\n\n"
                    "After all findings are generated, print a "
                    "summary table with columns: Title, Severity, "
                    "CVSS Score, Output File.\n\n"
                    "## Evidence Integrity Rules (MANDATORY)\n\n"
                    "1. Evidence anchors all claims — every "
                    "statement in a finding MUST trace to provided "
                    "evidence.\n"
                    "2. NEVER fabricate HTTP requests, responses, "
                    "endpoints, or URLs not present in the Burp "
                    "data.\n"
                    "3. NEVER reference screenshot files that do not "
                    "exist on disk.\n"
                    "4. CVSS scores MUST be computed via "
                    "`calculate_cvss` — never estimate or copy from "
                    "a template.\n"
                    "5. Templates provide severity baselines and "
                    "references — they are not content to expand or "
                    "pad.\n"
                    "6. Operator notes are authoritative — "
                    "incorporate the operator's severity assessments, "
                    "scope constraints, and impact analysis.\n"
                    "7. If evidence is insufficient to support a "
                    "claim, note the limitation rather than "
                    "fabricating support.\n"
                ),
            ),
        ]

    return server


def main() -> None:
    """Entry point for the finding-forge MCP server."""
    server = create_server()
    server.run()
