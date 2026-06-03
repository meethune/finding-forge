#!/usr/bin/env python3
"""Import templates from the template-generator CSV into Markdown files."""

import csv
import re
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = (
    _PROJECT_ROOT.parent.parent
    / "template-generator"
    / "data"
    / "ghostwriter-findings-library-import.csv"
)
OUTPUT_DIR = _PROJECT_ROOT / "src" / "finding_forge" / "templates" / "findings"


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _make_slug(title: str, seen: set[str]) -> str:
    prefix = title.split("—")[0].strip() if "—" in title else title
    slug = _slugify(prefix)
    if slug in seen:
        slug = _slugify(title)
    if slug in seen:
        i = 2
        while f"{slug}-{i}" in seen:
            i += 1
        slug = f"{slug}-{i}"
    seen.add(slug)
    return slug


def _extract_cwe_ids(title: str) -> list[str]:
    return re.findall(r"CWE-\d+", title)


def _extract_tags(title: str, finding_type: str, cwe_ids: list[str]) -> list[str]:
    tags: list[str] = []
    if finding_type:
        tags.append(finding_type.lower())
    tags.extend(c.lower() for c in cwe_ids)
    owasp_match = re.match(r"(A\d+|LLM\d+):2025", title)
    if owasp_match:
        tags.append(owasp_match.group(0).lower())
        if title.startswith("LLM"):
            tags.append("llm")
            tags.append("ai")
        else:
            tags.append("owasp")
    return tags


def _build_detection(host: str, network: str) -> str:
    parts: list[str] = []
    if host.strip():
        parts.append(f"**Host:** {host.strip()}")
    if network.strip():
        parts.append(f"**Network:** {network.strip()}")
    return "\n\n".join(parts)


def _format_references(refs_text: str) -> str:
    lines: list[str] = []
    for line in refs_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- "):
            lines.append(line)
        else:
            lines.append(f"- {line}")
    return "\n".join(lines)


def _build_template(row: dict[str, str], slug: str) -> str:
    cwe_ids = _extract_cwe_ids(row["title"])
    tags = _extract_tags(row["title"], row["finding_type"], cwe_ids)

    cwe_yaml = "\n".join(f"  - {c}" for c in cwe_ids) if cwe_ids else ""
    tags_yaml = "\n".join(f"  - {t}" for t in tags) if tags else ""

    frontmatter_lines = [
        "---",
        f'title: "{row["title"]}"',
    ]
    if cwe_ids:
        frontmatter_lines.append("cwe_ids:")
        frontmatter_lines.append(cwe_yaml)
    if tags:
        frontmatter_lines.append("tags:")
        frontmatter_lines.append(tags_yaml)
    if row["finding_type"]:
        frontmatter_lines.append(f"finding_type: {row['finding_type']}")
    frontmatter_lines.append("severity:")
    frontmatter_lines.append(f"  rating: {row['severity']}")
    frontmatter_lines.append("---")

    sections: list[str] = []
    sections.append(f"\n## Description\n\n{row['description']}")
    sections.append(f"\n## Impact\n\n{row['impact']}")
    sections.append(f"\n## Mitigation\n\n{row['mitigation']}")
    sections.append(f"\n## Replication Steps\n\n{row['replication_steps']}")

    refs = _format_references(row["references"])
    if refs:
        sections.append(f"\n## References\n\n{refs}")

    detection = _build_detection(
        row["host_detection_techniques"],
        row["network_detection_techniques"],
    )
    if detection:
        sections.append(f"\n## Detection\n\n{detection}")

    if row["finding_guidance"].strip():
        sections.append(f"\n## Guidance\n\n{row['finding_guidance']}")

    return "\n".join(frontmatter_lines) + "\n" + "\n".join(sections) + "\n"


def main() -> None:
    if not CSV_PATH.exists():
        print(f"CSV not found: {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for existing in OUTPUT_DIR.glob("*.md"):
        existing.unlink()

    seen_slugs: set[str] = set()
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        slug = _make_slug(row["title"], seen_slugs)
        content = _build_template(row, slug)
        output_path = OUTPUT_DIR / f"{slug}.md"
        output_path.write_text(content, encoding="utf-8")

    print(f"Generated {len(rows)} templates in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
