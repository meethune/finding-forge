"""Tests for the MCP server."""

import json
import os
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from finding_forge.models.schemas import Evidence, Finding
from finding_forge.server import _resolve_templates_dir, create_server


@pytest.fixture()
def templates_dir(tmp_path: Path) -> Path:
    """Create temporary templates directory with sample templates."""
    sqli = tmp_path / "sqli.md"
    sqli.write_text(
        dedent("""\
        ---
        title: SQL Injection
        cwe_ids:
          - CWE-89
        tags:
          - sqli
          - injection
        severity:
          rating: High
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
          cvss_score: 9.1
        ---

        ## Description

        SQL injection vulnerability.

        ## Impact

        Database compromise.

        ## Mitigation

        Use parameterized queries.

        ## Replication Steps

        1. Inject payload

        ## References

        - https://cwe.mitre.org/data/definitions/89.html

        ## Detection

        Monitor database logs.
        """)
    )
    return tmp_path


@pytest.fixture()
def burp_xml(tmp_path: Path) -> Path:
    """Create a sample Burp XML export file."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(
        '<?xml version="1.0"?>\n'
        '<items burpVersion="2024.0.0">\n'
        "  <item>\n"
        "    <url><![CDATA[https://app.example.com/login]]></url>\n"
        "    <host>app.example.com</host>\n"
        "    <port>443</port>\n"
        "    <protocol>https</protocol>\n"
        "    <method><![CDATA[POST]]></method>\n"
        "    <path><![CDATA[/login]]></path>\n"
        '    <request base64="false"><![CDATA[POST /login HTTP/1.1\r\n'
        "Host: app.example.com\r\n\r\nuser=admin]]></request>\n"
        "    <status>200</status>\n"
        '    <response base64="false"><![CDATA[HTTP/1.1 200 OK\r\n'
        "Content-Type: text/html\r\n\r\nOK]]></response>\n"
        "  </item>\n"
        "</items>\n"
    )
    return xml_file


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


class TestListFindingTemplatesTool:
    async def test_lists_templates(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool("list_finding_templates", {})
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["name"] == "sqli"


class TestGetFindingTemplateTool:
    async def test_gets_template(self, templates_dir: Path) -> None:
        server = create_server(templates_dir)
        result = await server.call_tool("get_finding_template", {"name": "sqli"})
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert data["title"] == "SQL Injection"


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
