"""Tests for export formatters."""

import json

import pytest

from finding_forge.export.formatters import (
    export_cervantes,
    export_csv_row,
    export_finding,
    export_json,
    export_markdown,
)
from finding_forge.models.schemas import (
    BurpRequest,
    Evidence,
    Finding,
    FindingSeverity,
)


@pytest.fixture()
def sample_finding() -> Finding:
    return Finding(
        title="SQL Injection in Login Form",
        description="The login form is vulnerable to SQL injection.",
        severity=FindingSeverity(
            rating="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_score=9.1,
            justification="Full database compromise",
        ),
        impact="An attacker can extract all database contents.",
        mitigation="Use parameterized queries.",
        replication_steps="1. Navigate to /login\n2. Enter ' OR 1=1--",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
        detection="Monitor database logs for anomalous queries.",
        cwe_ids=["CWE-89"],
    )


@pytest.fixture()
def finding_with_evidence() -> Finding:
    return Finding(
        title="SQL Injection in Login Form",
        description="The login form is vulnerable to SQL injection.",
        severity=FindingSeverity(rating="High", cvss_score=9.1),
        impact="An attacker can extract all database contents.",
        mitigation="Use parameterized queries.",
        replication_steps="1. Navigate to /login\n2. Enter ' OR 1=1--",
        evidence=[
            Evidence(
                title="Burp Capture - Login Bypass",
                evidence_type="http",
                operator_notes="Confirmed bypass with admin privileges.",
                screenshots=["screenshots/sqli_login.png"],
                scanner_findings=["SQLi detected by Burp Scanner"],
                requests=[
                    BurpRequest(
                        url="https://target.example.com/login",
                        method="POST",
                        host="target.example.com",
                        path="/login",
                        request_headers={
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        request_body="user=admin&pass=' OR 1=1--",
                        status_code=200,
                        response_headers={"Content-Type": "text/html"},
                        response_body="<html>Welcome admin</html>",
                    ),
                ],
            ),
            Evidence(
                title="Screenshot - Admin Dashboard",
                evidence_type="screenshot",
                screenshots=[
                    "screenshots/admin_dashboard.png",
                    "screenshots/admin_users.png",
                ],
            ),
        ],
    )


class TestExportJson:
    def test_returns_valid_json(self, sample_finding: Finding) -> None:
        result = export_json(sample_finding)
        data = json.loads(result)
        assert data["title"] == "SQL Injection in Login Form"

    def test_includes_all_fields(self, sample_finding: Finding) -> None:
        result = export_json(sample_finding)
        data = json.loads(result)
        assert "severity" in data
        assert "impact" in data
        assert "mitigation" in data
        assert "replication_steps" in data
        assert "references" in data
        assert "cwe_ids" in data

    def test_severity_nested(self, sample_finding: Finding) -> None:
        result = export_json(sample_finding)
        data = json.loads(result)
        assert data["severity"]["rating"] == "High"
        assert data["severity"]["cvss_score"] == 9.1


class TestExportCsvRow:
    def test_returns_flat_dict(self, sample_finding: Finding) -> None:
        row = export_csv_row(sample_finding)
        assert isinstance(row, dict)
        assert all(isinstance(v, str) for v in row.values())

    def test_contains_key_fields(self, sample_finding: Finding) -> None:
        row = export_csv_row(sample_finding)
        assert row["title"] == "SQL Injection in Login Form"
        assert row["severity_rating"] == "High"
        assert row["cvss_score"] == "9.1"

    def test_flattens_severity(self, sample_finding: Finding) -> None:
        row = export_csv_row(sample_finding)
        assert "severity_rating" in row
        assert "cvss_vector" in row
        assert "cvss_score" in row

    def test_joins_lists_as_strings(self, sample_finding: Finding) -> None:
        row = export_csv_row(sample_finding)
        assert "CWE-89" in row["cwe_ids"]
        assert "cwe.mitre.org" in row["references"]


class TestExportMarkdown:
    def test_includes_title_as_heading(self, sample_finding: Finding) -> None:
        md = export_markdown(sample_finding)
        assert "# SQL Injection in Login Form" in md

    def test_includes_severity_section(self, sample_finding: Finding) -> None:
        md = export_markdown(sample_finding)
        assert "High" in md
        assert "9.1" in md

    def test_includes_all_sections(self, sample_finding: Finding) -> None:
        md = export_markdown(sample_finding)
        assert "## Description" in md
        assert "## Impact" in md
        assert "## Mitigation" in md
        assert "## Replication Steps" in md
        assert "## References" in md

    def test_includes_detection_when_present(self, sample_finding: Finding) -> None:
        md = export_markdown(sample_finding)
        assert "## Detection" in md
        assert "database logs" in md

    def test_includes_evidence_section(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "## Evidence" in md

    def test_includes_evidence_title(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "### Burp Capture - Login Bypass" in md
        assert "### Screenshot - Admin Dashboard" in md

    def test_includes_evidence_type(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "**Type:** http" in md

    def test_includes_operator_notes(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "Confirmed bypass with admin privileges." in md

    def test_renders_screenshots_as_images(
        self, finding_with_evidence: Finding
    ) -> None:
        md = export_markdown(finding_with_evidence)
        assert "![sqli_login.png](screenshots/sqli_login.png)" in md
        assert "![admin_dashboard.png](screenshots/admin_dashboard.png)" in md

    def test_includes_scanner_findings(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "SQLi detected by Burp Scanner" in md

    def test_includes_request_details(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "POST" in md
        assert "https://target.example.com/login" in md
        assert "user=admin&pass=' OR 1=1--" in md

    def test_includes_response_details(self, finding_with_evidence: Finding) -> None:
        md = export_markdown(finding_with_evidence)
        assert "200" in md
        assert "<html>Welcome admin</html>" in md

    def test_omits_evidence_section_when_empty(self, sample_finding: Finding) -> None:
        md = export_markdown(sample_finding)
        assert "## Evidence" not in md

    def test_omits_detection_when_empty(self) -> None:
        finding = Finding(
            title="Test",
            description="Desc",
            severity=FindingSeverity(rating="Low"),
            impact="None",
            mitigation="N/A",
            replication_steps="N/A",
            detection="",
        )
        md = export_markdown(finding)
        assert "## Detection" not in md


class TestExportCervantes:
    def test_semicolon_delimited(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        assert ";" in result

    def test_has_20_columns(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        header_cols = lines[0].split(";")
        data_cols = lines[1].split(";")
        assert len(header_cols) == 20
        assert len(data_cols) == 20

    def test_maps_name(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert row[0] == "SQL Injection in Login Form"

    def test_maps_risk(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert row[3] == "High"

    def test_maps_cvss(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert row[9] == "9.1"
        assert "CVSS:3.1" in row[10]

    def test_maps_remediation(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert "parameterized queries" in row[11]

    def test_maps_poc_from_replication_steps(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert "Navigate to /login" in row[7]

    def test_status_defaults_to_open(self, sample_finding: Finding) -> None:
        result = export_cervantes(sample_finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert row[4] == "Open"

    def test_info_severity_mapping(self) -> None:
        finding = Finding(
            title="Info Finding",
            description="Test",
            severity=FindingSeverity(rating="Informational"),
            impact="None",
            mitigation="N/A",
            replication_steps="N/A",
        )
        result = export_cervantes(finding)
        lines = result.strip().splitlines()
        row = lines[1].split(";")
        assert row[3] == "Info"


class TestExportFinding:
    @pytest.mark.parametrize("fmt", ["json", "csv", "markdown", "cervantes"])
    def test_dispatches_all_formats(self, sample_finding: Finding, fmt: str) -> None:
        result = export_finding(sample_finding, fmt)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_json_format(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "json")
        data = json.loads(result)
        assert data["title"] == "SQL Injection in Login Form"

    def test_csv_format(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "csv")
        data = json.loads(result)
        assert data["title"] == "SQL Injection in Login Form"

    def test_markdown_format(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "markdown")
        assert "# SQL Injection in Login Form" in result

    def test_cervantes_format(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "cervantes")
        assert ";" in result
        assert "SQL Injection in Login Form" in result

    def test_cervantes_csv_alias(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "cervantes-csv")
        assert ";" in result
        assert "SQL Injection in Login Form" in result

    def test_md_alias(self, sample_finding: Finding) -> None:
        result = export_finding(sample_finding, "md")
        assert "# SQL Injection in Login Form" in result

    def test_invalid_format_raises(self, sample_finding: Finding) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            export_finding(sample_finding, "docx")
