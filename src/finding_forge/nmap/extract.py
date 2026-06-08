"""Nmap XML scan output extraction."""

from pathlib import Path

from libnmap.parser import NmapParser

from finding_forge.models.schemas import NmapScriptResult, NmapService


def parse_nmap_xml(xml_path: Path) -> list[NmapService]:
    """Parse an nmap XML output file into NmapService objects."""
    if not xml_path.exists():
        msg = f"Nmap XML file not found: {xml_path}"
        raise FileNotFoundError(msg)

    report = NmapParser.parse_fromfile(str(xml_path))

    services: list[NmapService] = []
    for host in report.hosts:
        hostname = host.hostnames[0] if host.hostnames else ""
        os_matches = host.os_match_probabilities()
        os_match = os_matches[0].name if os_matches else ""

        for svc in host.services:
            scripts = [
                NmapScriptResult(script_id=s["id"], output=s["output"])
                for s in svc.scripts_results
            ]
            services.append(
                NmapService(
                    host=host.address,
                    hostname=hostname,
                    port=svc.port,
                    protocol=svc.protocol,
                    state=svc.state,
                    service=svc.service,
                    version=svc.banner,
                    os_match=os_match,
                    scripts=scripts,
                )
            )

    return services


def filter_by_scope(
    services: list[NmapService],
    target_hosts: list[str],
) -> list[NmapService]:
    """Filter services to those matching target hosts (by IP or hostname)."""
    host_set = set(target_hosts)
    return [s for s in services if s.host in host_set or s.hostname in host_set]


def extract_nmap_data(
    xml_path: Path,
    target_hosts: list[str],
) -> list[NmapService]:
    """Parse nmap XML, filter to scope, and return structured services."""
    return filter_by_scope(parse_nmap_xml(xml_path), target_hosts)
