"""Pydantic data models for evidence, findings, and engagement sessions."""

from pydantic import BaseModel


class Evidence(BaseModel):
    """A single piece of evidence captured during testing."""

    ...


class Finding(BaseModel):
    """A drafted finding ready for export to a reporting platform."""

    ...


class EngagementSession(BaseModel):
    """One testing session's captured evidence and metadata."""

    ...
