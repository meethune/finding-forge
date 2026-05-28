"""Evidence aggregation — combines Burp data, screenshots, and operator notes."""

from datetime import date
from pathlib import Path

from finding_forge.models.schemas import (
    BurpRequest,
    EngagementSession,
    Evidence,
)


def create_session(
    engagement_id: str,
    target: str,
    session_date: date | None = None,
    operator: str = "",
) -> EngagementSession:
    """Create a new engagement session."""
    return EngagementSession(
        engagement_id=engagement_id,
        target=target,
        date=session_date or date.today(),
        operator=operator,
    )


def add_evidence(
    session: EngagementSession,
    title: str,
    evidence_type: str,
    requests: list[BurpRequest] | None = None,
    screenshots: list[str] | None = None,
    operator_notes: str = "",
) -> EngagementSession:
    """Add an evidence item to a session. Returns a new session (immutable)."""
    new_evidence = Evidence(
        title=title,
        evidence_type=evidence_type,
        requests=requests or [],
        screenshots=screenshots or [],
        operator_notes=operator_notes,
    )
    return session.model_copy(update={"evidence": [*session.evidence, new_evidence]})


def save_session(session: EngagementSession, output_path: Path) -> Path:
    """Serialize session to JSON file."""
    output_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
    return output_path


def load_session(session_path: Path) -> EngagementSession:
    """Load a session from a JSON file."""
    if not session_path.exists():
        msg = f"Session file not found: {session_path}"
        raise FileNotFoundError(msg)
    return EngagementSession.model_validate_json(
        session_path.read_text(encoding="utf-8")
    )
