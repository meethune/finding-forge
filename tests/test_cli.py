"""Smoke tests for the finding-forge CLI."""

import json
from pathlib import Path

from click.testing import CliRunner

from finding_forge.cli import forge
from finding_forge.models.schemas import Finding, FindingSeverity


class TestForgeGroup:
    def test_help_exits_cleanly(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["--help"])
        assert result.exit_code == 0
        assert "Order from chaos" in result.output

    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["--version"])
        assert result.exit_code == 0
        assert "1.1.1" in result.output


class TestCaptureCommand:
    def test_help_exits_cleanly(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["capture", "--help"])
        assert result.exit_code == 0
        assert "Capture evidence" in result.output

    def test_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["capture", "--help"])
        assert "--target" in result.output
        assert "--engagement" in result.output
        assert "--burp-xml" in result.output
        assert "--output" in result.output

    def test_creates_evidence_file(self, tmp_path: Path) -> None:
        output = tmp_path / "evidence.json"
        runner = CliRunner()
        result = runner.invoke(
            forge,
            [
                "capture",
                "--target",
                "https://test.com",
                "--engagement",
                "ENG-001",
                "--notes",
                "Testing session",
                "--output",
                str(output),
            ],
        )
        assert result.exit_code == 0
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["engagement_id"] == "ENG-001"


class TestExportCommand:
    def test_help_exits_cleanly(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["export", "--help"])
        assert result.exit_code == 0
        assert "Export a finding" in result.output

    def test_exports_to_stdout(self, tmp_path: Path) -> None:
        finding = Finding(
            title="Test Finding",
            description="A test",
            severity=FindingSeverity(rating="Low"),
            impact="None",
            mitigation="N/A",
            replication_steps="N/A",
        )
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(finding.model_dump_json())

        runner = CliRunner()
        result = runner.invoke(
            forge,
            ["export", "--finding", str(finding_path), "--format", "markdown"],
        )
        assert result.exit_code == 0
        assert "# Test Finding" in result.output

    def test_exports_to_file(self, tmp_path: Path) -> None:
        finding = Finding(
            title="Test Finding",
            description="A test",
            severity=FindingSeverity(rating="Low"),
            impact="None",
            mitigation="N/A",
            replication_steps="N/A",
        )
        finding_path = tmp_path / "finding.json"
        finding_path.write_text(finding.model_dump_json())
        output = tmp_path / "output.md"

        runner = CliRunner()
        result = runner.invoke(
            forge,
            [
                "export",
                "--finding",
                str(finding_path),
                "--format",
                "markdown",
                "--output",
                str(output),
            ],
        )
        assert result.exit_code == 0
        assert output.exists()
        assert "# Test Finding" in output.read_text()
