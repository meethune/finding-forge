"""Smoke tests for the finding-forge CLI."""

from click.testing import CliRunner

from finding_forge.cli import forge


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
        assert "0.1.0" in result.output


class TestCaptureCommand:
    def test_help_exits_cleanly(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["capture", "--help"])
        assert result.exit_code == 0
        assert "Capture evidence" in result.output


class TestDraftCommand:
    def test_help_exits_cleanly(self) -> None:
        runner = CliRunner()
        result = runner.invoke(forge, ["draft", "--help"])
        assert result.exit_code == 0
        assert "Draft findings" in result.output
