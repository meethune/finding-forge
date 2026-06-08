"""Tests for nmap XML data extraction."""

from pathlib import Path

import pytest
from libnmap.parser import NmapParserException

from finding_forge.nmap.extract import (
    extract_nmap_data,
    filter_by_scope,
    parse_nmap_xml,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestParseNmapXml:
    def test_parses_all_services(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        assert len(services) == 6

    def test_extracts_host_and_port(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        ssh = next(s for s in services if s.host == "10.0.0.1" and s.port == 22)
        assert ssh.protocol == "tcp"
        assert ssh.state == "open"

    def test_extracts_service_name(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        ssh = next(s for s in services if s.host == "10.0.0.1" and s.port == 22)
        assert ssh.service == "ssh"

    def test_extracts_version_banner(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        ssh = next(s for s in services if s.host == "10.0.0.1" and s.port == 22)
        assert "OpenSSH" in ssh.version
        assert "8.9p1" in ssh.version

    def test_extracts_hostname(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        svc = next(s for s in services if s.host == "10.0.0.1")
        assert svc.hostname == "web.example.com"

    def test_empty_hostname_when_missing(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        svc = next(s for s in services if s.host == "10.0.0.2")
        assert svc.hostname == ""

    def test_extracts_os_match(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        svc = next(s for s in services if s.host == "10.0.0.1")
        assert "Linux" in svc.os_match

    def test_empty_os_when_missing(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        svc = next(s for s in services if s.host == "10.0.0.2")
        assert svc.os_match == ""

    def test_extracts_nse_scripts(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        http = next(s for s in services if s.port == 80)
        assert len(http.scripts) == 1
        assert http.scripts[0].script_id == "http-title"
        assert http.scripts[0].output == "Test Page"

    def test_includes_filtered_services(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        mysql = next(s for s in services if s.port == 3306)
        assert mysql.state == "filtered"

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_nmap_xml(Path("/nonexistent/scan.xml"))

    def test_malformed_xml_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.xml"
        bad_file.write_text("not xml at all")
        with pytest.raises(NmapParserException):
            parse_nmap_xml(bad_file)


class TestFilterByScope:
    def test_filters_by_ip(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        filtered = filter_by_scope(services, ["10.0.0.1"])
        assert len(filtered) == 4
        assert all(s.host == "10.0.0.1" for s in filtered)

    def test_filters_by_hostname(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        filtered = filter_by_scope(services, ["web.example.com"])
        assert len(filtered) == 4
        assert all(s.hostname == "web.example.com" for s in filtered)

    def test_multiple_targets(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        filtered = filter_by_scope(services, ["10.0.0.1", "10.0.0.2"])
        assert len(filtered) == 6

    def test_empty_scope_returns_empty(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        filtered = filter_by_scope(services, [])
        assert filtered == []

    def test_no_match_returns_empty(self) -> None:
        services = parse_nmap_xml(FIXTURES_DIR / "sample_nmap_scan.xml")
        filtered = filter_by_scope(services, ["192.168.1.1"])
        assert filtered == []


class TestExtractNmapData:
    def test_end_to_end(self) -> None:
        results = extract_nmap_data(
            FIXTURES_DIR / "sample_nmap_scan.xml",
            ["10.0.0.1"],
        )
        assert len(results) == 4
        assert all(r.host == "10.0.0.1" for r in results)

    def test_returns_empty_for_no_scope_match(self) -> None:
        results = extract_nmap_data(
            FIXTURES_DIR / "sample_nmap_scan.xml",
            ["192.168.1.1"],
        )
        assert results == []

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            extract_nmap_data(Path("/nonexistent/scan.xml"), ["10.0.0.1"])
