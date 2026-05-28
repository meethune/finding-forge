"""CLI entry points for finding-forge."""

import click

from finding_forge import __version__


@click.group()
@click.version_option(version=__version__, prog_name="finding-forge")
def forge() -> None:
    """Order from chaos. Evidence capture and AI-assisted finding drafting."""


@forge.command()
def capture() -> None:
    """Capture evidence from a testing session."""
    click.echo("pentest-capture is not yet implemented.")
    raise SystemExit(0)


@forge.command()
def draft() -> None:
    """Draft findings from captured evidence using AI."""
    click.echo("pentest-draft is not yet implemented.")
    raise SystemExit(0)
