"""Pydantic data models for evidence, findings, and engagement sessions."""

from datetime import date, datetime

from pydantic import BaseModel, Field


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


class EngagementSession(BaseModel):
    """One testing session's captured evidence and metadata."""

    engagement_id: str
    target: str
    date: date
    operator: str = ""
    evidence: list[Evidence] = Field(default_factory=list)


class FindingSeverity(BaseModel):
    """CVSS scoring with justification."""

    rating: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    justification: str = ""


class Finding(BaseModel):
    """A drafted finding ready for export to a reporting platform."""

    title: str
    description: str
    severity: FindingSeverity
    impact: str
    mitigation: str
    replication_steps: str
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    detection: str = ""
    cwe_ids: list[str] = Field(default_factory=list)


class FindingTemplate(BaseModel):
    """A reusable finding template from the template library."""

    name: str
    title: str
    description: str
    severity: FindingSeverity
    impact: str
    mitigation: str
    replication_steps: str
    references: list[str] = Field(default_factory=list)
    detection: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    finding_type: str = ""
    guidance: str = ""
