"""Tests for evidence capture module."""

import json
from datetime import date
from pathlib import Path

import pytest

from finding_forge.evidence.capture import (
    add_evidence,
    create_session,
    load_session,
    save_session,
)
from finding_forge.models.schemas import BurpRequest


class TestCreateSession:
    def test_creates_with_required_fields(self) -> None:
        session = create_session(
            engagement_id="ENG-2025-042",
            target="https://app.example.com",
        )
        assert session.engagement_id == "ENG-2025-042"
        assert session.target == "https://app.example.com"
        assert session.evidence == []

    def test_defaults_date_to_today(self) -> None:
        session = create_session(
            engagement_id="ENG-001",
            target="https://test.com",
        )
        assert session.date == date.today()

    def test_custom_date(self) -> None:
        session = create_session(
            engagement_id="ENG-001",
            target="https://test.com",
            session_date=date(2025, 6, 15),
        )
        assert session.date == date(2025, 6, 15)

    def test_operator(self) -> None:
        session = create_session(
            engagement_id="ENG-001",
            target="https://test.com",
            operator="jdoe",
        )
        assert session.operator == "jdoe"


class TestAddEvidence:
    def test_adds_evidence_to_session(self) -> None:
        session = create_session("ENG-001", "https://test.com")
        updated = add_evidence(
            session,
            title="SQL Injection in login",
            evidence_type="sqli",
            operator_notes="Confirmed error-based SQLi",
        )
        assert len(updated.evidence) == 1
        assert updated.evidence[0].title == "SQL Injection in login"
        assert updated.evidence[0].operator_notes == "Confirmed error-based SQLi"

    def test_adds_multiple_evidence(self) -> None:
        session = create_session("ENG-001", "https://test.com")
        session = add_evidence(session, title="SQLi", evidence_type="sqli")
        session = add_evidence(session, title="XSS", evidence_type="xss")
        assert len(session.evidence) == 2

    def test_preserves_existing_evidence(self) -> None:
        session = create_session("ENG-001", "https://test.com")
        session = add_evidence(session, title="First", evidence_type="sqli")
        session = add_evidence(session, title="Second", evidence_type="xss")
        assert session.evidence[0].title == "First"
        assert session.evidence[1].title == "Second"

    def test_with_burp_requests(self) -> None:
        req = BurpRequest(
            url="https://test.com/login",
            method="POST",
            host="test.com",
            path="/login",
            request_headers={},
            status_code=500,
            response_headers={},
        )
        session = create_session("ENG-001", "https://test.com")
        updated = add_evidence(
            session,
            title="SQLi",
            evidence_type="sqli",
            requests=[req],
        )
        assert len(updated.evidence[0].requests) == 1

    def test_with_screenshots(self) -> None:
        session = create_session("ENG-001", "https://test.com")
        updated = add_evidence(
            session,
            title="XSS",
            evidence_type="xss",
            screenshots=["/path/to/xss-proof.png"],
        )
        assert updated.evidence[0].screenshots == ["/path/to/xss-proof.png"]

    def test_does_not_mutate_original(self) -> None:
        session = create_session("ENG-001", "https://test.com")
        updated = add_evidence(session, title="SQLi", evidence_type="sqli")
        assert len(session.evidence) == 0
        assert len(updated.evidence) == 1


class TestSaveAndLoadSession:
    def test_save_creates_json_file(self, tmp_path: Path) -> None:
        session = create_session("ENG-001", "https://test.com")
        output = save_session(session, tmp_path / "session.json")
        assert output.exists()
        assert output.suffix == ".json"

    def test_saved_file_is_valid_json(self, tmp_path: Path) -> None:
        session = create_session("ENG-001", "https://test.com")
        output = save_session(session, tmp_path / "session.json")
        data = json.loads(output.read_text())
        assert data["engagement_id"] == "ENG-001"

    def test_roundtrip(self, tmp_path: Path) -> None:
        session = create_session("ENG-001", "https://test.com", operator="analyst")
        session = add_evidence(
            session, title="SQLi", evidence_type="sqli", operator_notes="Confirmed"
        )
        output = save_session(session, tmp_path / "session.json")
        loaded = load_session(output)
        assert loaded == session

    def test_load_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_session(Path("/nonexistent/session.json"))

    def test_save_returns_path(self, tmp_path: Path) -> None:
        session = create_session("ENG-001", "https://test.com")
        result = save_session(session, tmp_path / "out.json")
        assert result == tmp_path / "out.json"
