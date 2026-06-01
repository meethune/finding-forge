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
            "Pentest evidence capture and finding drafting tools. "
            "Use templates and evidence to draft security findings."
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
          evidence (list[{title, evidence_type}], optional)

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
                    '  "cwe_ids": ["CWE-XX"]\n'
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

    return server


def main() -> None:
    """Entry point for the finding-forge MCP server."""
    server = create_server()
    server.run()
