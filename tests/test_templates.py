"""Tests for the template library module."""

from pathlib import Path
from textwrap import dedent

import pytest

from finding_forge.templates.library import (
    get_template,
    list_templates,
    load_template,
    match_templates,
)


@pytest.fixture()
def templates_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with sample template files."""
    sqli = tmp_path / "sqli.md"
    sqli.write_text(
        dedent("""\
        ---
        title: SQL Injection
        cwe_ids:
          - CWE-89
        tags:
          - sqli
          - injection
          - database
        severity:
          rating: High
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
          cvss_score: 9.1
          justification: "Full database compromise"
        ---

        ## Description

        SQL injection vulnerability.

        ## Impact

        Database compromise.

        ## Mitigation

        Use parameterized queries.

        ## Replication Steps

        1. Inject payload

        ## References

        - https://cwe.mitre.org/data/definitions/89.html

        ## Detection

        Monitor database logs.
        """)
    )

    xss = tmp_path / "xss-reflected.md"
    xss.write_text(
        dedent("""\
        ---
        title: Reflected Cross-Site Scripting (XSS)
        cwe_ids:
          - CWE-79
        tags:
          - xss
          - reflected
          - injection
        severity:
          rating: Medium
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
          cvss_score: 6.1
        ---

        ## Description

        Reflected XSS vulnerability.

        ## Impact

        Session hijacking.

        ## Mitigation

        Encode output.

        ## Replication Steps

        1. Inject script tag

        ## References

        - https://cwe.mitre.org/data/definitions/79.html

        ## Detection

        Deploy WAF rules.
        """)
    )

    return tmp_path


class TestLoadTemplate:
    def test_loads_valid_template(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "sqli.md")
        assert tmpl.name == "sqli"
        assert tmpl.title == "SQL Injection"
        assert tmpl.severity.rating == "High"
        assert tmpl.severity.cvss_score == 9.1
        assert "CWE-89" in tmpl.cwe_ids
        assert "sqli" in tmpl.tags

    def test_extracts_body_sections(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "sqli.md")
        assert "SQL injection vulnerability" in tmpl.description
        assert "Database compromise" in tmpl.impact
        assert "parameterized queries" in tmpl.mitigation
        assert "Inject payload" in tmpl.replication_steps
        assert "cwe.mitre.org" in tmpl.references[0]
        assert "database logs" in tmpl.detection

    def test_name_from_filename_stem(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "xss-reflected.md")
        assert tmpl.name == "xss-reflected"

    def test_missing_file_raises(self, templates_dir: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_template(templates_dir / "nonexistent.md")


class TestListTemplates:
    def test_lists_all_templates(self, templates_dir: Path) -> None:
        templates = list_templates(templates_dir)
        names = {t.name for t in templates}
        assert names == {"sqli", "xss-reflected"}

    def test_empty_directory(self, tmp_path: Path) -> None:
        templates = list_templates(tmp_path)
        assert templates == []

    def test_ignores_non_markdown_files(self, templates_dir: Path) -> None:
        (templates_dir / ".gitkeep").touch()
        (templates_dir / "notes.txt").write_text("not a template")
        templates = list_templates(templates_dir)
        names = {t.name for t in templates}
        assert names == {"sqli", "xss-reflected"}


class TestGetTemplate:
    def test_gets_by_name(self, templates_dir: Path) -> None:
        tmpl = get_template(templates_dir, "sqli")
        assert tmpl.title == "SQL Injection"

    def test_gets_hyphenated_name(self, templates_dir: Path) -> None:
        tmpl = get_template(templates_dir, "xss-reflected")
        assert tmpl.title == "Reflected Cross-Site Scripting (XSS)"

    def test_not_found_raises(self, templates_dir: Path) -> None:
        with pytest.raises(FileNotFoundError):
            get_template(templates_dir, "nonexistent")


class TestMatchTemplates:
    def test_matches_by_tag(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "sqli")
        assert len(results) >= 1
        assert results[0].name == "sqli"

    def test_matches_by_title(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "Cross-Site Scripting")
        assert len(results) >= 1
        assert results[0].name == "xss-reflected"

    def test_matches_by_cwe(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "CWE-89")
        assert len(results) >= 1
        assert results[0].name == "sqli"

    def test_shared_tag_matches_multiple(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "injection")
        assert len(results) == 2

    def test_no_match_returns_empty(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "buffer overflow")
        assert results == []

    def test_max_results_limits_output(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "injection", max_results=1)
        assert len(results) == 1

    def test_case_insensitive(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "SQL INJECTION")
        assert len(results) >= 1
