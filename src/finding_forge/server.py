"""MCP server for finding-forge — pentest evidence capture and finding drafting."""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import Message, UserMessage

from finding_forge.burp.extract import extract_burp_data
from finding_forge.evidence.capture import add_evidence, create_session
from finding_forge.export.formatters import export_finding as _export_finding
from finding_forge.models.schemas import Finding
from finding_forge.templates.library import (
    get_template,
    list_templates,
    match_templates,
)

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
        return json.dumps([r.model_dump(mode="json") for r in results], indent=2)

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
        return json.dumps([t.model_dump(mode="json") for t in templates], indent=2)

    @server.tool()
    def get_finding_template(name: str) -> str:
        """Get a specific finding template by name."""
        tmpl = get_template(resolved_dir, name)
        return tmpl.model_dump_json(indent=2)

    @server.tool()
    def match_finding_templates(query: str, max_results: int = 5) -> str:
        """Find templates matching a text query by tags, title, and CWE IDs."""
        results = match_templates(resolved_dir, query, max_results)
        return json.dumps([t.model_dump(mode="json") for t in results], indent=2)

    @server.tool()
    def export_finding(finding_json: str, fmt: str) -> str:
        """Export a Finding as JSON, CSV, or Markdown."""
        finding = Finding.model_validate_json(finding_json)
        return _export_finding(finding, fmt)  # type: ignore[arg-type]

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
                template_context = (
                    f"\n\n## Reference Template: {tmpl.title}\n\n"
                    f"**Description:** {tmpl.description}\n\n"
                    f"**Default Severity:** {tmpl.severity.rating}"
                )
                if tmpl.severity.cvss_vector:
                    template_context += f" ({tmpl.severity.cvss_vector})"
                template_context += (
                    f"\n\n**Impact:** {tmpl.impact}\n\n"
                    f"**Mitigation:** {tmpl.mitigation}\n\n"
                    f"**Replication Steps:** {tmpl.replication_steps}\n\n"
                    f"**Detection:** {tmpl.detection}\n\n"
                    f"**References:** {', '.join(tmpl.references)}\n\n"
                    f"**CWE:** {', '.join(tmpl.cwe_ids)}"
                )
            except FileNotFoundError:
                template_context = (
                    f"\n\nTemplate '{template_name}' not found. "
                    "Draft the finding without a template reference."
                )

        return [
            UserMessage(
                content=(
                    "You are a penetration test report writer. "
                    "Draft a complete security finding based on the evidence below. "
                    "Your output must include:\n\n"
                    "1. **Title** — Clear, specific finding title\n"
                    "2. **Description** — Technical description of the vulnerability\n"
                    "3. **Severity** — CVSS 3.1 rating, vector, "
                    "score, and justification\n"
                    "4. **Impact** — Business and technical impact\n"
                    "5. **Mitigation** — Specific remediation steps\n"
                    "6. **Replication Steps** — Step-by-step "
                    "reproduction using the evidence\n"
                    "7. **References** — CWE, OWASP, and other authoritative sources\n"
                    "8. **Detection** — How to detect this "
                    "vulnerability or exploitation attempts\n\n"
                    "Rules:\n"
                    "- Never fabricate evidence — only reference what is provided\n"
                    "- Mark any inferred details clearly\n"
                    "- Use the template as a starting point if provided, "
                    "but customize with engagement-specific evidence\n\n"
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
