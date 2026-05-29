"""Output formatters — exports drafted findings to CSV, JSON, Markdown, or DOCX."""

import json
from collections.abc import Callable

from finding_forge.models.schemas import Finding


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
    }


def export_markdown(finding: Finding) -> str:
    """Export a finding as formatted Markdown."""
    lines: list[str] = []
    lines.append(f"# {finding.title}")
    lines.append("")
    lines.append(f"**Severity:** {finding.severity.rating}")
    if finding.severity.cvss_score is not None:
        lines.append(f"**CVSS Score:** {finding.severity.cvss_score}")
    if finding.severity.cvss_vector:
        lines.append(f"**CVSS Vector:** {finding.severity.cvss_vector}")
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


def _escape_cervantes(value: str) -> str:
    return value.replace(";", ",").replace("\n", "<br>")


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
        finding.severity.cvss_vector or "",
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
