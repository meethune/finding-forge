"""CLI entry points for finding-forge."""

from pathlib import Path
from urllib.parse import urlparse

import click

from finding_forge import __version__
from finding_forge.burp.extract import extract_burp_data
from finding_forge.evidence.capture import (
    add_evidence,
    create_session,
    save_session,
)
from finding_forge.export.formatters import export_finding
from finding_forge.models.schemas import Finding


@click.group()
@click.version_option(version=__version__, prog_name="finding-forge")
def forge() -> None:
    """Order from chaos. Evidence capture and finding export for pentest reporting."""


@forge.command()
@click.option("--target", required=True, help="Target URL or scope identifier.")
@click.option("--engagement", required=True, help="Engagement identifier.")
@click.option(
    "--burp-xml",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Burp Suite XML proxy history export file.",
)
@click.option("--operator", default="", help="Operator name.")
@click.option("--notes", default="", help="Operator notes for this session.")
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=Path("evidence.json"),
    help="Output file path for the evidence session.",
)
def capture(
    target: str,
    engagement: str,
    burp_xml: Path | None,
    operator: str,
    notes: str,
    output: Path,
) -> None:
    """Capture evidence from a testing session."""
    session = create_session(
        engagement_id=engagement,
        target=target,
        operator=operator,
    )

    if burp_xml:
        target_hosts = [urlparse(target).hostname or target]
        requests = extract_burp_data(burp_xml, target_hosts)
        if requests:
            session = add_evidence(
                session,
                title=f"Burp proxy history ({len(requests)} requests)",
                evidence_type="burp-export",
                requests=requests,
                operator_notes=notes,
            )
            click.echo(f"Extracted {len(requests)} requests from Burp export.")

    if not session.evidence and notes:
        session = add_evidence(
            session,
            title="Operator notes",
            evidence_type="notes",
            operator_notes=notes,
        )

    result = save_session(session, output)
    click.echo(f"Evidence saved to {result}")


@forge.command(name="export")
@click.option(
    "--finding",
    "finding_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Finding JSON file to export.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "csv", "markdown", "cervantes"]),
    default="markdown",
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path (stdout if omitted).",
)
def export_cmd(
    finding_path: Path,
    fmt: str,
    output: Path | None,
) -> None:
    """Export a finding in the specified format."""
    finding = Finding.model_validate_json(finding_path.read_text(encoding="utf-8"))
    result = export_finding(finding, fmt)

    if output:
        output.write_text(result, encoding="utf-8")
        click.echo(f"Finding exported to {output}")
    else:
        click.echo(result)
