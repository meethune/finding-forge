"""Pydantic data models for evidence, findings, and engagement sessions."""

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class BurpRequest(BaseModel):
    """A single HTTP request/response pair extracted from Burp Suite."""

    url: str
    method: str
    host: str
    path: str
    request_headers: dict[str, str]
    request_body: str | None = None
    status_code: int
    response_headers: dict[str, str]
    response_body: str | None = None
    timestamp: datetime | None = None
    flags: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """A single piece of evidence captured during testing."""

    title: str
    evidence_type: str
    requests: list[BurpRequest] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    operator_notes: str = ""
    scanner_findings: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "title" not in data and "description" in data:
            data["title"] = data.pop("description")
        if "evidence_type" not in data and "type" in data:
            data["evidence_type"] = data.pop("type")
        data.setdefault("title", "Evidence")
        data.setdefault("evidence_type", "other")
        return data


class EngagementSession(BaseModel):
    """One testing session's captured evidence and metadata."""

    engagement_id: str
    target: str
    date: date
    operator: str = ""
    evidence: list[Evidence] = Field(default_factory=list)


_VALID_RATINGS: set[str] = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
}

_RATING_ALIASES: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}


class FindingSeverity(BaseModel):
    """CVSS scoring with justification."""

    rating: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    justification: str = ""

    @model_validator(mode="after")
    def _auto_compute_score(self) -> "FindingSeverity":
        if self.rating and self.rating not in ("", "Unknown"):
            normalized = _RATING_ALIASES.get(self.rating.lower())
            if normalized:
                self.rating = normalized
            elif self.rating not in _VALID_RATINGS:
                msg = (
                    f"Invalid severity rating: {self.rating!r}. "
                    f"Must be one of: {', '.join(sorted(_VALID_RATINGS))}"
                )
                raise ValueError(msg)
        if self.cvss_vector and self.cvss_score is None:
            from finding_forge.cvss.calculator import score_from_vector

            result = score_from_vector(self.cvss_vector)
            self.cvss_score = result.score
            if self.rating in ("", "Unknown"):
                self.rating = result.rating
        return self


_FINDING_FIELD_ALIASES: dict[str, str] = {
    "remediation": "mitigation",
    "steps": "replication_steps",
    "reproduction_steps": "replication_steps",
    "poc": "replication_steps",
    "proof_of_concept": "replication_steps",
    "cvss": "severity",
    "risk": "severity",
    "cwe": "cwe_ids",
    "cwes": "cwe_ids",
}


class _FindingBase(BaseModel):
    """Shared fields between findings and finding templates."""

    title: str
    description: str
    severity: FindingSeverity
    impact: str
    mitigation: str
    replication_steps: str
    references: list[str] = Field(default_factory=list)
    detection: str = ""
    cwe_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for alias, canonical in _FINDING_FIELD_ALIASES.items():
            if alias in data and canonical not in data:
                data[canonical] = data.pop(alias)
        sev = data.get("severity")
        if isinstance(sev, str):
            data["severity"] = {"rating": sev}
        return data


class Finding(_FindingBase):
    """A drafted finding ready for export to a reporting platform."""

    evidence: list[Evidence] = Field(default_factory=list)


class FindingTemplate(_FindingBase):
    """A reusable finding template from the template library."""

    name: str
    tags: list[str] = Field(default_factory=list)
    finding_type: str = ""
    guidance: str = ""
