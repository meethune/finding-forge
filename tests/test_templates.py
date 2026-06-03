"""Tests for the template library module."""

from importlib.resources import files
from pathlib import Path

import pytest

from finding_forge.templates.library import (
    get_template,
    list_templates,
    load_template,
    match_templates,
)


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

    def test_reads_finding_type(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "sqli.md")
        assert tmpl.finding_type == "Web"

    def test_reads_guidance_section(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "sqli.md")
        assert "error-based or blind SQLi" in tmpl.guidance

    def test_missing_finding_type_defaults_empty(self, templates_dir: Path) -> None:
        tmpl = load_template(templates_dir / "xss-reflected.md")
        assert tmpl.finding_type == "Cloud"

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

    def test_skips_malformed_template(self, templates_dir: Path) -> None:
        (templates_dir / "bad.md").write_text("no frontmatter here")
        templates = list_templates(templates_dir)
        names = {t.name for t in templates}
        assert names == {"sqli", "xss-reflected"}

    def test_skips_template_with_invalid_yaml(self, templates_dir: Path) -> None:
        (templates_dir / "bad-yaml.md").write_text("---\n: invalid: yaml:\n---\n")
        templates = list_templates(templates_dir)
        names = {t.name for t in templates}
        assert names == {"sqli", "xss-reflected"}


class TestLoadTemplateEdgeCases:
    def test_empty_frontmatter_raises(self, tmp_path: Path) -> None:
        tmpl_file = tmp_path / "empty.md"
        tmpl_file.write_text("---\n\n---\n## Description\nTest.\n")
        with pytest.raises(ValueError, match="not a YAML mapping"):
            load_template(tmpl_file)


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

    def test_rejects_name_with_forward_slash(self, templates_dir: Path) -> None:
        with pytest.raises(ValueError, match="Invalid template name"):
            get_template(templates_dir, "../etc/passwd")

    def test_rejects_name_with_backslash(self, templates_dir: Path) -> None:
        with pytest.raises(ValueError, match="Invalid template name"):
            get_template(templates_dir, "..\\etc\\passwd")

    def test_rejects_symlink_escaping_dir(self, templates_dir: Path) -> None:
        outside_file = templates_dir.parent / "secret.md"
        outside_file.write_text(
            "---\ntitle: Secret\nseverity:\n  rating: High\n---\n"
            "## Description\nSecret.\n## Impact\nSecret.\n"
            "## Mitigation\nSecret.\n## Replication Steps\nSecret.\n"
        )
        (templates_dir / "evil.md").symlink_to(outside_file)
        with pytest.raises(ValueError, match="Invalid template name"):
            get_template(templates_dir, "evil")

    def test_allows_dotted_names(self, templates_dir: Path) -> None:
        dotted = templates_dir / "cwe-89.2.md"
        dotted.write_text(
            "---\ntitle: CWE 89.2\nseverity:\n  rating: High\n---\n"
            "## Description\nTest.\n## Impact\nTest.\n"
            "## Mitigation\nTest.\n## Replication Steps\nTest.\n"
        )
        tmpl = get_template(templates_dir, "cwe-89.2")
        assert tmpl.title == "CWE 89.2"


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

    def test_matches_by_finding_type(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "web")
        assert len(results) >= 1
        assert results[0].name == "sqli"

    def test_matches_cloud_type(self, templates_dir: Path) -> None:
        results = match_templates(templates_dir, "cloud")
        assert len(results) >= 1
        assert results[0].name == "xss-reflected"


_REAL_TEMPLATES_DIR = Path(
    str(files("finding_forge").joinpath("templates", "findings"))
)


class TestBundledTemplates:
    def test_bundled_templates_dir_exists(self) -> None:
        assert _REAL_TEMPLATES_DIR.exists()
        assert _REAL_TEMPLATES_DIR.is_dir()

    def test_all_templates_parse(self) -> None:
        templates = list_templates(_REAL_TEMPLATES_DIR)
        assert len(templates) == 78

    def test_no_empty_titles(self) -> None:
        templates = list_templates(_REAL_TEMPLATES_DIR)
        for tmpl in templates:
            assert tmpl.title, f"Template {tmpl.name} has empty title"

    def test_no_empty_descriptions(self) -> None:
        templates = list_templates(_REAL_TEMPLATES_DIR)
        for tmpl in templates:
            assert tmpl.description, f"Template {tmpl.name} has empty description"

    def test_all_have_severity(self) -> None:
        templates = list_templates(_REAL_TEMPLATES_DIR)
        for tmpl in templates:
            assert tmpl.severity.rating, f"Template {tmpl.name} missing severity"

    def test_unique_names(self) -> None:
        templates = list_templates(_REAL_TEMPLATES_DIR)
        names = [t.name for t in templates]
        assert len(names) == len(set(names))
