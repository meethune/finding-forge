"""Tests for Pydantic data models."""

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from finding_forge.models.schemas import (
    BurpRequest,
    EngagementSession,
    Evidence,
    Finding,
    FindingSeverity,
    FindingTemplate,
)


class TestBurpRequest:
    def test_minimal_construction(self) -> None:
        req = BurpRequest(
            url="https://example.com/login",
            method="POST",
            host="example.com",
            path="/login",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            status_code=200,
            response_headers={"Content-Type": "text/html"},
        )
        assert req.url == "https://example.com/login"
        assert req.method == "POST"
        assert req.status_code == 200

    def test_optional_fields_default(self) -> None:
        req = BurpRequest(
            url="https://example.com/",
            method="GET",
            host="example.com",
            path="/",
            request_headers={},
            status_code=200,
            response_headers={},
        )
        assert req.request_body is None
        assert req.response_body is None
        assert req.timestamp is None
        assert req.flags == []

    def test_full_construction(self) -> None:
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=UTC)
        req = BurpRequest(
            url="https://example.com/api/users",
            method="GET",
            host="example.com",
            path="/api/users",
            request_headers={"Authorization": "Bearer tok123"},
            request_body=None,
            status_code=403,
            response_headers={"Content-Type": "application/json"},
            response_body='{"error": "forbidden"}',
            timestamp=ts,
            flags=["interesting"],
        )
        assert req.timestamp == ts
        assert "interesting" in req.flags

    def test_serialization_roundtrip(self) -> None:
        req = BurpRequest(
            url="https://example.com/",
            method="GET",
            host="example.com",
            path="/",
            request_headers={"Host": "example.com"},
            status_code=200,
            response_headers={},
        )
        data = req.model_dump(mode="json")
        reconstructed = BurpRequest.model_validate(data)
        assert reconstructed == req


class TestEvidence:
    def test_minimal_construction(self) -> None:
        ev = Evidence(title="SQL Injection in login", evidence_type="sqli")
        assert ev.title == "SQL Injection in login"
        assert ev.evidence_type == "sqli"
        assert ev.requests == []
        assert ev.screenshots == []
        assert ev.operator_notes == ""
        assert ev.scanner_findings == []

    def test_with_requests(self) -> None:
        req = BurpRequest(
            url="https://example.com/login",
            method="POST",
            host="example.com",
            path="/login",
            request_headers={},
            status_code=500,
            response_headers={},
        )
        ev = Evidence(
            title="SQL Injection",
            evidence_type="sqli",
            requests=[req],
            operator_notes="Error-based SQLi confirmed",
        )
        assert len(ev.requests) == 1
        assert ev.operator_notes == "Error-based SQLi confirmed"

    def test_serialization_roundtrip(self) -> None:
        ev = Evidence(
            title="XSS in search",
            evidence_type="xss",
            screenshots=["/path/to/screenshot.png"],
            scanner_findings=["Reflected XSS detected"],
        )
        data = ev.model_dump(mode="json")
        reconstructed = Evidence.model_validate(data)
        assert reconstructed == ev


class TestEngagementSession:
    def test_minimal_construction(self) -> None:
        session = EngagementSession(
            engagement_id="ENG-2025-042",
            target="https://app.example.com",
            date=date(2025, 6, 15),
        )
        assert session.engagement_id == "ENG-2025-042"
        assert session.operator == ""
        assert session.evidence == []

    def test_with_evidence(self) -> None:
        ev = Evidence(title="SQLi", evidence_type="sqli")
        session = EngagementSession(
            engagement_id="ENG-2025-042",
            target="https://app.example.com",
            date=date(2025, 6, 15),
            operator="jdoe",
            evidence=[ev],
        )
        assert len(session.evidence) == 1
        assert session.operator == "jdoe"

    def test_serialization_roundtrip(self) -> None:
        session = EngagementSession(
            engagement_id="ENG-001",
            target="https://test.example.com",
            date=date(2025, 1, 1),
            operator="analyst",
        )
        data = session.model_dump(mode="json")
        reconstructed = EngagementSession.model_validate(data)
        assert reconstructed == session


class TestFindingSeverity:
    def test_minimal(self) -> None:
        sev = FindingSeverity(rating="High")
        assert sev.rating == "High"
        assert sev.cvss_vector is None
        assert sev.cvss_score is None
        assert sev.justification == ""

    def test_full(self) -> None:
        sev = FindingSeverity(
            rating="Critical",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            justification="Unauthenticated RCE over network",
        )
        assert sev.cvss_score == 9.8


class TestFinding:
    @pytest.fixture()
    def sample_finding(self) -> Finding:
        return Finding(
            title="SQL Injection in Login Form",
            description="The login form is vulnerable to SQL injection.",
            severity=FindingSeverity(
                rating="High",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_score=9.1,
            ),
            impact="An attacker can extract all database contents.",
            mitigation="Use parameterized queries.",
            replication_steps="1. Navigate to /login\n2. Enter ' OR 1=1-- in username",
            references=["https://cwe.mitre.org/data/definitions/89.html"],
            cwe_ids=["CWE-89"],
        )

    def test_construction(self, sample_finding: Finding) -> None:
        assert sample_finding.title == "SQL Injection in Login Form"
        assert sample_finding.severity.rating == "High"

    def test_optional_fields_default(self, sample_finding: Finding) -> None:
        assert sample_finding.evidence == []
        assert sample_finding.detection == ""

    def test_serialization_roundtrip(self, sample_finding: Finding) -> None:
        data = sample_finding.model_dump(mode="json")
        reconstructed = Finding.model_validate(data)
        assert reconstructed == sample_finding

    def test_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="Incomplete")  # type: ignore[call-arg]


class TestFindingTemplate:
    def test_construction(self) -> None:
        tmpl = FindingTemplate(
            name="sqli",
            title="SQL Injection",
            description="Application is vulnerable to SQL injection.",
            severity=FindingSeverity(rating="High"),
            impact="Database compromise.",
            mitigation="Use parameterized queries.",
            replication_steps="1. Inject payload\n2. Observe response",
            tags=["sqli", "injection", "owasp-a03"],
        )
        assert tmpl.name == "sqli"
        assert "injection" in tmpl.tags

    def test_optional_fields_default(self) -> None:
        tmpl = FindingTemplate(
            name="test",
            title="Test",
            description="Test template",
            severity=FindingSeverity(rating="Low"),
            impact="Minimal",
            mitigation="N/A",
            replication_steps="N/A",
        )
        assert tmpl.references == []
        assert tmpl.detection == ""
        assert tmpl.cwe_ids == []
        assert tmpl.tags == []
        assert tmpl.finding_type == ""
        assert tmpl.guidance == ""

    def test_finding_type_and_guidance(self) -> None:
        tmpl = FindingTemplate(
            name="a01-2025",
            title="A01:2025 — Broken Access Control",
            description="Access control failures.",
            severity=FindingSeverity(rating="High"),
            impact="Unauthorized access.",
            mitigation="Deny by default.",
            replication_steps="1. Test access controls.",
            finding_type="Web",
            guidance="Use for broad access control findings.",
        )
        assert tmpl.finding_type == "Web"
        assert tmpl.guidance == "Use for broad access control findings."

    def test_serialization_roundtrip(self) -> None:
        tmpl = FindingTemplate(
            name="xss",
            title="XSS",
            description="Cross-site scripting",
            severity=FindingSeverity(rating="Medium"),
            impact="Session hijacking",
            mitigation="Encode output",
            replication_steps="1. Inject script tag",
            tags=["xss"],
            cwe_ids=["CWE-79"],
        )
        data = tmpl.model_dump(mode="json")
        reconstructed = FindingTemplate.model_validate(data)
        assert reconstructed == tmpl
