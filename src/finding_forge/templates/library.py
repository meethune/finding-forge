"""Template loading, listing, and matching for the findings library."""

import re
from pathlib import Path

import yaml

from finding_forge.models.schemas import FindingSeverity, FindingTemplate

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

_SECTION_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)


def _parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    match = _FRONTMATTER_RE.match(text)
    if not match:
        msg = "Template missing YAML frontmatter"
        raise ValueError(msg)
    raw_yaml = match.group(1)
    body = match.group(2)
    meta: dict[str, object] = yaml.safe_load(raw_yaml)
    return meta, body


def _parse_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    headings = list(_SECTION_RE.finditer(body))
    for i, heading in enumerate(headings):
        name = heading.group(1).strip().lower()
        start = heading.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(body)
        sections[name] = body[start:end].strip()
    return sections


def _extract_references(text: str) -> list[str]:
    return [
        line.lstrip("- ").strip()
        for line in text.splitlines()
        if line.strip().startswith("- ")
    ]


def load_template(template_path: Path) -> FindingTemplate:
    """Parse a Markdown template file into a FindingTemplate."""
    if not template_path.exists():
        msg = f"Template not found: {template_path}"
        raise FileNotFoundError(msg)

    text = template_path.read_text(encoding="utf-8")
    meta, body = _parse_frontmatter(text)
    sections = _parse_sections(body)

    severity_data = meta.get("severity", {})
    if not isinstance(severity_data, dict):
        severity_data = {"rating": str(severity_data)}

    return FindingTemplate(
        name=template_path.stem,
        title=str(meta.get("title", template_path.stem)),
        description=sections.get("description", ""),
        severity=FindingSeverity(**severity_data),
        impact=sections.get("impact", ""),
        mitigation=sections.get("mitigation", ""),
        replication_steps=sections.get("replication steps", ""),
        references=_extract_references(sections.get("references", "")),
        detection=sections.get("detection", ""),
        cwe_ids=meta.get("cwe_ids", []),  # type: ignore[arg-type]
        tags=meta.get("tags", []),  # type: ignore[arg-type]
        finding_type=str(meta.get("finding_type", "")),
        guidance=sections.get("guidance", ""),
    )


def list_templates(templates_dir: Path) -> list[FindingTemplate]:
    """List all templates in a directory."""
    if not templates_dir.exists():
        return []
    return sorted(
        (load_template(p) for p in templates_dir.glob("*.md")),
        key=lambda t: t.name,
    )


def get_template(templates_dir: Path, name: str) -> FindingTemplate:
    """Get a specific template by filename stem."""
    path = templates_dir / f"{name}.md"
    return load_template(path)


def match_templates(
    templates_dir: Path,
    query: str,
    max_results: int = 5,
) -> list[FindingTemplate]:
    """Find templates matching a text query by tags, title, and CWE IDs."""
    all_templates = list_templates(templates_dir)
    query_lower = query.lower()
    query_terms = query_lower.split()

    scored: list[tuple[int, FindingTemplate]] = []
    for tmpl in all_templates:
        score = 0
        searchable = " ".join(
            [tmpl.title.lower(), tmpl.finding_type.lower()]
            + [t.lower() for t in tmpl.tags]
            + [c.lower() for c in tmpl.cwe_ids]
        )
        for term in query_terms:
            if term in searchable:
                score += 1
        if score > 0:
            scored.append((score, tmpl))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [tmpl for _, tmpl in scored[:max_results]]
