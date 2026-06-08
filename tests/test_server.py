"""Tests for the MCP server."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from finding_forge.models.schemas import Evidence, Finding
from finding_forge.server import (
    _BUNDLED_TEMPLATES_DIR,
    _resolve_templates_dir,
    create_server,
)


class TestResolveTemplatesDir:
    def test_override_takes_precedence(self, tmp_path: Path) -> None:
        result = _resolve_templates_dir(tmp_path)
        assert result == tmp_path

    def test_env_var_used_when_no_override(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"FINDING_FORGE_TEMPLATES_DIR": str(tmp_path)}):
            result = _resolve_templates_dir()
            assert result == tmp_path

    def test_falls_back_to_bundled(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = _resolve_templates_dir()
            assert result.name == "findings"
            assert result.parent.name == "templates"

    def test_bundled_path_resolves_to_existing_dir(self) -> None:
        assert _BUNDLED_TEMPLATES_DIR.exists()
        assert _BUNDLED_TEMPLATES_DIR.is_dir()


class TestModelCoercion:
    def test_finding_severity_string_to_object(self) -> None:
        finding = Finding.model_validate(
            {
                "title": "Test",
                "description": "Desc",
                "severity": "Critical",
                "impact": "High impact",
                "mitigation": "Fix it",
                "replication_steps": "1. Do thing",
            }
        )
        assert finding.severity.rating == "Critical"

    def test_finding_remediation_alias(self) -> None:
        finding = Finding.model_validate(
            {
                "title": "Test",
                "description": "Desc",
                "severity": {"rating": "High"},
                "impact": "Impact",
                "remediation": "Use parameterized queries",
                "replication_steps": "Steps",
            }
        )
        assert finding.mitigation == "Use parameterized queries"

    def test_finding_steps_alias(self) -> None:
        finding = Finding.model_validate(
            {
                "title": "Test",
                "description": "Desc",
                "severity": {"rating": "Low"},
                "impact": "None",
                "mitigation": "N/A",
                "steps": "1. Go to page",
            }
        )
        assert finding.replication_steps == "1. Go to page"

    def test_finding_missing_required_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding.model_validate(
                {
                    "title": "Test",
                    "description": "Desc",
                    "severity": "Medium",
                    "impact": "Impact",
                }
            )

    def test_evidence_type_alias(self) -> None:
        ev = Evidence.model_validate(
            {"type": "request", "description": "POST /login payload"}
        )
        assert ev.title == "POST /login payload"
        assert ev.evidence_type == "request"

    def test_evidence_defaults(self) -> None:
        ev = Evidence.model_validate({"content": "some data"})
        assert ev.title == "Evidence"
        assert ev.evidence_type == "other"


class TestServerToolsRegistered:
    async def test_all_tools_registered(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        tools = await server.list_tools()
        tool_names = {t.name for t in tools}
        assert "extract_burp" in tool_names
        assert "capture_evidence" in tool_names
        assert "list_finding_templates" in tool_names
        assert "get_finding_template" in tool_names
        assert "match_finding_templates" in tool_names
        assert "export_finding" in tool_names
        assert "calculate_cvss" in tool_names
        assert "validate_finding" in tool_names
        assert "extract_nmap" in tool_names


class TestValidateFindingTool:
    async def test_valid_finding(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        finding_json = json.dumps(
            {
                "title": "Test",
                "description": "Desc",
                "severity": {"rating": "High"},
                "impact": "Impact",
                "mitigation": "Fix",
                "replication_steps": "Steps",
            }
        )
        result = await server.call_tool(
            "validate_finding", {"finding_json": finding_json}
        )
        content, _is_error = result
        assert content[0].text == "valid"  # type: ignore[union-attr]

    async def test_invalid_finding_returns_errors(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        finding_json = json.dumps({"title": "Incomplete"})
        result = await server.call_tool(
            "validate_finding", {"finding_json": finding_json}
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        assert "Validation errors" in text
        assert "mitigation" in text.lower()


class TestCalculateCvssTool:
    async def test_calculates_score(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool(
            "calculate_cvss",
            {
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "H",
                "availability": "H",
            },
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert data["score"] == 9.8
        assert data["rating"] == "Critical"
        assert "CVSS:3.1" in data["vector"]


class TestServerPromptsRegistered:
    async def test_draft_finding_prompt_registered(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        prompts = await server.list_prompts()
        prompt_names = {p.name for p in prompts}
        assert "draft_finding" in prompt_names


class TestServerResourcesRegistered:
    async def test_template_resource_template_registered(
        self, templates_dir: Path
    ) -> None:
        server = create_server(templates_dir)
        resource_templates = await server.list_resource_templates()
        uris = {str(rt.uriTemplate) for rt in resource_templates}
        assert any("templates://findings/" in u for u in uris)


class TestExtractBurpTool:
    async def test_extracts_burp_data(
        self, templates_dir: Path, burp_xml: Path
    ) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool(
            "extract_burp",
            {
                "xml_path": str(burp_xml),
                "target_hosts": ["app.example.com"],
            },
        )
        content, _is_error = result
        assert len(content) > 0
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["host"] == "app.example.com"


class TestExtractNmapTool:
    async def test_extracts_nmap_data(
        self, templates_dir: Path, tmp_path: Path
    ) -> None:
        nmap_xml = tmp_path / "scan.xml"
        nmap_xml.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sV 10.0.0.1"'
            ' start="1717632000" startstr="Mon Jun  3 12:00:00 2026"'
            ' version="7.94" xmloutputversion="1.05">\n'
            '<host starttime="1717632001" endtime="1717632010">\n'
            '  <status state="up" reason="syn-ack"/>\n'
            '  <address addr="10.0.0.1" addrtype="ipv4"/>\n'
            "  <hostnames/>\n"
            "  <ports>\n"
            '    <port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="ssh" product="OpenSSH" version="8.9p1"'
            ' method="probed" conf="10"/></port>\n'
            "  </ports>\n"
            "</host>\n"
            "<runstats>"
            '<finished time="1717632020" elapsed="20"/>'
            '<hosts up="1" down="0" total="1"/>'
            "</runstats>\n"
            "</nmaprun>\n"
        )
        server = create_server(templates_dir)
        result = await server.call_tool(
            "extract_nmap",
            {
                "xml_path": str(nmap_xml),
                "target_hosts": ["10.0.0.1"],
            },
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[index,union-attr]
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["host"] == "10.0.0.1"
        assert data[0]["port"] == 22
        assert data[0]["service"] == "ssh"


class TestListFindingTemplatesTool:
    async def test_lists_templates(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool("list_finding_templates", {})
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert len(data) == 2
        names = {t["name"] for t in data}
        assert names == {"sqli", "xss-reflected"}


class TestGetFindingTemplateTool:
    async def test_gets_template(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool("get_finding_template", {"name": "sqli"})
        content, _is_error = result
        data = json.loads(content[0].text)  # type: ignore[union-attr]
        assert data["title"] == "SQL Injection"

    async def test_rejects_path_traversal(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        with pytest.raises(ToolError, match="Invalid template name"):
            await server.call_tool("get_finding_template", {"name": "../etc/passwd"})


class TestMatchFindingTemplatesTool:
    async def test_matches_templates(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool("match_finding_templates", {"query": "sqli"})
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert len(data) >= 1
        assert data[0]["name"] == "sqli"


class TestCaptureEvidenceTool:
    async def test_creates_session(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool(
            "capture_evidence",
            {
                "engagement_id": "ENG-001",
                "target": "https://test.com",
                "title": "SQLi in login",
                "evidence_type": "sqli",
                "operator_notes": "Confirmed",
            },
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert data["engagement_id"] == "ENG-001"
        assert len(data["evidence"]) == 1


class TestExportFindingTool:
    async def test_exports_markdown(self, templates_dir: Path) -> None:
        finding_data = {
            "title": "Test Finding",
            "description": "A test",
            "severity": {"rating": "Low"},
            "impact": "None",
            "mitigation": "N/A",
            "replication_steps": "N/A",
        }
        server = create_server(templates_dir)
        result = await server.call_tool(
            "export_finding",
            {"finding_json": json.dumps(finding_data), "fmt": "markdown"},
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        assert "# Test Finding" in text

    async def test_exports_markdown_with_evidence(self, templates_dir: Path) -> None:
        finding_data = {
            "title": "XSS in Search",
            "description": "Reflected XSS.",
            "severity": {"rating": "High"},
            "impact": "Session hijacking.",
            "mitigation": "Encode output.",
            "replication_steps": "1. Enter payload",
            "evidence": [
                {
                    "title": "XSS Alert Box",
                    "evidence_type": "screenshot",
                    "operator_notes": "Alert triggered in search field",
                    "screenshots": ["screenshots/xss-alert.png"],
                },
                {
                    "title": "Malicious Request",
                    "evidence_type": "http_request",
                    "requests": [
                        {
                            "url": "https://target.com/search?q=<script>alert(1)</script>",
                            "method": "GET",
                            "host": "target.com",
                            "path": "/search?q=<script>alert(1)</script>",
                            "request_headers": {"Host": "target.com"},
                            "status_code": 200,
                            "response_headers": {"Content-Type": "text/html"},
                            "response_body": (
                                "<p>Results for: <script>alert(1)</script></p>"
                            ),
                        }
                    ],
                },
            ],
        }
        server = create_server(templates_dir)
        result = await server.call_tool(
            "export_finding",
            {"finding_json": json.dumps(finding_data), "fmt": "markdown"},
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        assert "![XSS Alert Box](screenshots/xss-alert.png)" in text
        assert "Alert triggered in search field" in text
        assert "GET /search?q=<script>alert(1)</script> HTTP/1.1" in text
        assert "<p>Results for: <script>alert(1)</script></p>" in text

    async def test_export_finding_docstring_documents_evidence_fields(
        self, templates_dir: Path
    ) -> None:
        server = create_server(templates_dir)
        tools = await server.list_tools()
        export_tool = next(t for t in tools if t.name == "export_finding")
        desc = export_tool.description or ""
        assert "screenshots" in desc
        assert "operator_notes" in desc
        assert "requests" in desc


class TestDraftFindingPrompt:
    async def test_returns_messages(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt(
            "draft_finding",
            {
                "evidence_summary": "SQL injection in the login form",
                "template_name": "sqli",
            },
        )
        assert len(result.messages) > 0

    async def test_includes_template_content(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt(
            "draft_finding",
            {"evidence_summary": "SQL injection found", "template_name": "sqli"},
        )
        all_text = " ".join(str(m.content) for m in result.messages)
        assert "SQL Injection" in all_text

    async def test_works_without_template(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt(
            "draft_finding",
            {"evidence_summary": "Found a vulnerability"},
        )
        assert len(result.messages) > 0

    async def test_output_schema_includes_evidence(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt(
            "draft_finding",
            {"evidence_summary": "XSS found"},
        )
        all_text = " ".join(str(m.content) for m in result.messages)
        assert '"evidence"' in all_text
        assert "screenshots" in all_text
        assert "operator_notes" in all_text


class TestForgePrompt:
    async def test_forge_prompt_registered(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        prompts = await server.list_prompts()
        prompt_names = {p.name for p in prompts}
        assert "forge" in prompt_names

    async def test_forge_returns_messages_with_zero_args(
        self, templates_dir: Path
    ) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt("forge", {})
        assert len(result.messages) > 0

    async def test_forge_contains_tool_references(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt("forge", {})
        text = " ".join(str(m.content) for m in result.messages)
        for tool in [
            "extract_burp",
            "match_finding_templates",
            "calculate_cvss",
            "validate_finding",
            "export_finding",
        ]:
            assert tool in text, f"forge prompt missing reference to {tool}"

    async def test_forge_contains_integrity_rules(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt("forge", {})
        text = " ".join(str(m.content) for m in result.messages)
        assert "fabricate" in text.lower()
        assert "evidence" in text.lower()

    async def test_forge_contains_artifact_patterns(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt("forge", {})
        text = " ".join(str(m.content) for m in result.messages)
        assert ".xml" in text
        assert ".png" in text
        assert ".md" in text

    async def test_forge_instructs_image_syntax(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.get_prompt("forge", {})
        text = " ".join(str(m.content) for m in result.messages)
        assert "![" in text


class TestServerInstructions:
    def test_instructions_describe_workflow(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        instructions = server._mcp_server.instructions or ""
        for tool in [
            "extract_burp",
            "match_finding_templates",
            "calculate_cvss",
            "validate_finding",
            "export_finding",
        ]:
            assert tool in instructions, f"instructions missing {tool}"

    def test_instructions_mention_forge_prompt(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        instructions = server._mcp_server.instructions or ""
        assert "forge" in instructions.lower()

    def test_instructions_are_provider_agnostic(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        instructions = server._mcp_server.instructions or ""
        for term in ["Claude", "Anthropic", "GPT", "OpenAI"]:
            assert term not in instructions, (
                f"instructions contain provider-specific term: {term}"
            )
