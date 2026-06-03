"""Output formatters — exports drafted findings to CSV, JSON, Markdown, or DOCX."""

import http
import json
from collections.abc import Callable

from finding_forge.models.schemas import BurpRequest, Evidence, Finding


def export_json(finding: Finding) -> str:
    """Export a finding as a JSON string."""
    return finding.model_dump_json(indent=2)


def export_csv_row(finding: Finding) -> dict[str, str]:
    """Export a finding as a flat dict suitable for CSV writing."""
    return {
        "title": finding.title,
        "description": finding.description,
        "severity_rating": finding.severity.rating,
        "cvss_vector": finding.severity.cvss_vector or "",
        "cvss_score": (
            str(finding.severity.cvss_score)
            if finding.severity.cvss_score is not None
            else ""
        ),
        "justification": finding.severity.justification,
        "impact": finding.impact,
        "mitigation": finding.mitigation,
        "replication_steps": finding.replication_steps,
        "references": "; ".join(finding.references),
        "detection": finding.detection,
        "cwe_ids": "; ".join(finding.cwe_ids),
        "evidence": json.dumps([e.model_dump(mode="json") for e in finding.evidence]),
    }


def _render_http_request(req: BurpRequest, lines: list[str]) -> None:
    """Render a BurpRequest as HTTP request/response code blocks."""
    lines.append("**Request:**")
    lines.append("")
    lines.append("```http")
    lines.append(f"{req.method} {req.path} HTTP/1.1")
    lines.append(f"Host: {req.host}")
    for name, value in req.request_headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
    if req.request_body:
        lines.append("")
        lines.append(req.request_body)
    lines.append("```")
    lines.append("")

    lines.append("**Response:**")
    lines.append("")
    lines.append("```http")
    try:
        phrase = http.HTTPStatus(req.status_code).phrase
    except ValueError:
        phrase = ""
    lines.append(f"HTTP/1.1 {req.status_code} {phrase}")
    for name, value in req.response_headers.items():
        lines.append(f"{name}: {value}")
    if req.response_body:
        lines.append("")
        lines.append(req.response_body)
    lines.append("```")
    lines.append("")


def _render_evidence(evidence: Evidence, lines: list[str]) -> None:
    """Render a single evidence item as Markdown subsections."""
    lines.append(f"### {evidence.title}")
    lines.append("")

    if evidence.operator_notes:
        lines.append(evidence.operator_notes)
        lines.append("")

    for screenshot in evidence.screenshots:
        lines.append(f"![{evidence.title}]({screenshot})")
    if evidence.screenshots:
        lines.append("")

    if evidence.scanner_findings:
        lines.append("**Scanner Findings:**")
        lines.append("")
        for finding_text in evidence.scanner_findings:
            lines.append(f"- {finding_text}")
        lines.append("")

    for req in evidence.requests:
        _render_http_request(req, lines)


def export_markdown(finding: Finding) -> str:
    """Export a finding as formatted Markdown."""
    lines: list[str] = []
    lines.append(f"# {finding.title}")
    lines.append("")
    lines.append(f"**Severity:** {finding.severity.rating}  ")
    if finding.severity.cvss_score is not None:
        lines.append(f"**CVSS Score:** {finding.severity.cvss_score}  ")
    if finding.severity.cvss_vector:
        lines.append(f"**CVSS Vector:** {finding.severity.cvss_vector}  ")
    if finding.cwe_ids:
        lines.append(f"**CWE:** {', '.join(finding.cwe_ids)}")
    lines.append("")

    lines.append("## Description")
    lines.append("")
    lines.append(finding.description)
    lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(finding.impact)
    lines.append("")

    lines.append("## Mitigation")
    lines.append("")
    lines.append(finding.mitigation)
    lines.append("")

    lines.append("## Replication Steps")
    lines.append("")
    lines.append(finding.replication_steps)
    lines.append("")

    if finding.evidence:
        lines.append("## Evidence")
        lines.append("")
        for item in finding.evidence:
            _render_evidence(item, lines)

    if finding.references:
        lines.append("## References")
        lines.append("")
        for ref in finding.references:
            lines.append(f"- {ref}")
        lines.append("")

    if finding.detection:
        lines.append("## Detection")
        lines.append("")
        lines.append(finding.detection)
        lines.append("")

    return "\n".join(lines)


_CERVANTES_RISK_MAP: dict[str, str] = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Info",
}

_CERVANTES_COLUMNS = [
    "Name",
    "Template",
    "VulnCategory",
    "Risk",
    "Status",
    "CVE",
    "Description",
    "Poc",
    "Impact",
    "CVSS3",
    "CVSSVector",
    "Remediation",
    "RemediationComplexity",
    "RemediationPriority",
    "OwaspRisk",
    "OwaspVector",
    "OwaspLikehood",
    "OwaspImpact",
    "MitreTechniques",
    "MitreValues",
]


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _escape_cervantes(value: str) -> str:
    escaped = value.replace(";", ",").replace("\n", "<br>")
    if escaped and escaped[0] in _FORMULA_PREFIXES:
        escaped = f"'{escaped}"
    return escaped


def export_cervantes(finding: Finding) -> str:
    """Export a finding as Cervantes-compatible semicolon-delimited CSV."""
    risk = _CERVANTES_RISK_MAP.get(finding.severity.rating, "Info")
    cvss_score = (
        str(finding.severity.cvss_score)
        if finding.severity.cvss_score is not None
        else "0.0"
    )

    row = [
        _escape_cervantes(finding.title),
        "False",
        "General",
        risk,
        "Open",
        "",
        _escape_cervantes(finding.description),
        _escape_cervantes(finding.replication_steps),
        _escape_cervantes(finding.impact),
        cvss_score,
        _escape_cervantes(finding.severity.cvss_vector or ""),
        _escape_cervantes(finding.mitigation),
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]

    header = ";".join(_CERVANTES_COLUMNS)
    data = ";".join(row)
    return f"{header}\n{data}\n"


_FORMAT_DISPATCH: dict[str, Callable[[Finding], str]] = {
    "json": export_json,
    "csv": lambda f: json.dumps(export_csv_row(f), indent=2),
    "markdown": export_markdown,
    "md": export_markdown,
    "cervantes": export_cervantes,
    "cervantes-csv": export_cervantes,
    "cervantes_csv": export_cervantes,
}


def export_finding(finding: Finding, fmt: str) -> str:
    """Export a finding in the specified format."""
    formatter = _FORMAT_DISPATCH.get(fmt)
    if not formatter:
        msg = f"Unsupported export format: {fmt}"
        raise ValueError(msg)
    return formatter(finding)
