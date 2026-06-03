"""Tests for Burp Suite data extraction."""

import base64
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from finding_forge.burp.extract import (
    extract_burp_data,
    filter_by_scope,
    parse_burp_xml,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestParseBurpXml:
    def test_parses_all_items(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert len(requests) == 4

    def test_extracts_url_and_method(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        login_req = requests[0]
        assert login_req.url == "https://app.example.com/login"
        assert login_req.method == "POST"

    def test_extracts_host_and_path(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert requests[0].host == "app.example.com"
        assert requests[0].path == "/login"

    def test_extracts_status_code(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert requests[0].status_code == 302
        assert requests[1].status_code == 200

    def test_decodes_base64_request(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert requests[0].request_body is not None
        assert "username=admin" in requests[0].request_body

    def test_decodes_base64_response(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert requests[1].response_body is not None
        assert "admin" in requests[1].response_body

    def test_extracts_request_headers(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        assert "Host" in requests[0].request_headers
        assert requests[0].request_headers["Host"] == "app.example.com"

    def test_extracts_response_headers(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        login_resp = requests[0]
        assert "Location" in login_resp.response_headers
        assert login_resp.response_headers["Location"] == "/dashboard"

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_burp_xml(Path("/nonexistent/burp.xml"))

    def test_invalid_xml_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.xml"
        bad_file.write_text("not xml at all")
        with pytest.raises(ET.ParseError):
            parse_burp_xml(bad_file)

    def test_handles_non_base64_request(self, tmp_path: Path) -> None:
        xml_content = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url><![CDATA[https://example.com/]]></url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method><![CDATA[GET]]></method>\n"
            "    <path><![CDATA[/]]></path>\n"
            '    <request base64="false"><![CDATA[GET / HTTP/1.1\r\n'
            "Host: example.com\r\n\r\n]]></request>\n"
            "    <status>200</status>\n"
            '    <response base64="false"><![CDATA[HTTP/1.1 200 OK\r\n'
            "Content-Type: text/html\r\n\r\n<html></html>]]></response>\n"
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "plain.xml"
        xml_file.write_text(xml_content)
        requests = parse_burp_xml(xml_file)
        assert len(requests) == 1


class TestFilterByScope:
    def test_filters_to_target_host(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        filtered = filter_by_scope(requests, ["app.example.com"])
        assert len(filtered) == 3
        assert all(r.host == "app.example.com" for r in filtered)

    def test_filters_out_of_scope(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        filtered = filter_by_scope(requests, ["app.example.com"])
        hosts = {r.host for r in filtered}
        assert "other.example.com" not in hosts

    def test_multiple_target_hosts(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        filtered = filter_by_scope(requests, ["app.example.com", "other.example.com"])
        assert len(filtered) == 4

    def test_empty_scope_returns_none(self) -> None:
        requests = parse_burp_xml(FIXTURES_DIR / "sample_burp_export.xml")
        filtered = filter_by_scope(requests, [])
        assert filtered == []


class TestExtractBurpData:
    def test_end_to_end(self) -> None:
        results = extract_burp_data(
            FIXTURES_DIR / "sample_burp_export.xml",
            ["app.example.com"],
        )
        assert len(results) == 3
        assert all(r.host == "app.example.com" for r in results)

    def test_returns_empty_for_no_scope_match(self) -> None:
        results = extract_burp_data(
            FIXTURES_DIR / "sample_burp_export.xml",
            ["nonexistent.example.com"],
        )
        assert results == []


class TestXmlSafety:
    def test_rejects_xml_entity_expansion(self, tmp_path: Path) -> None:
        xml_content = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE foo [\n"
            '  <!ENTITY xxe "BOOM">\n'
            "]>\n"
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url>&xxe;</url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path>/</path>\n"
            '    <request base64="false">'
            "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
            "</request>\n"
            "    <status>200</status>\n"
            '    <response base64="false">'
            "HTTP/1.1 200 OK\\r\\n\\r\\n</response>\n"
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "xxe.xml"
        xml_file.write_text(xml_content)
        with pytest.raises(ValueError):
            parse_burp_xml(xml_file)


class TestCorruptBase64:
    def test_handles_corrupt_base64_request(self, tmp_path: Path) -> None:
        xml_content = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url>https://example.com/</url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path>/</path>\n"
            '    <request base64="true">!!!not-valid-base64!!!</request>\n'
            "    <status>200</status>\n"
            '    <response base64="false">HTTP/1.1 200 OK\r\n\r\nOK</response>\n'
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "corrupt.xml"
        xml_file.write_text(xml_content)
        requests = parse_burp_xml(xml_file)
        assert len(requests) == 1

    def test_handles_corrupt_base64_response(self, tmp_path: Path) -> None:
        valid_request = base64.b64encode(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ).decode()
        xml_content = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url>https://example.com/</url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path>/</path>\n"
            f'    <request base64="true">{valid_request}</request>\n'
            "    <status>200</status>\n"
            '    <response base64="true">!!!corrupt!!!</response>\n'
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "corrupt_resp.xml"
        xml_file.write_text(xml_content)
        requests = parse_burp_xml(xml_file)
        assert len(requests) == 1


class TestNonNumericStatusCode:
    def test_handles_non_numeric_status_code(self, tmp_path: Path) -> None:
        xml_content = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url>https://example.com/</url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path>/</path>\n"
            '    <request base64="false">'
            "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
            "</request>\n"
            "    <status>abc</status>\n"
            '    <response base64="false">'
            "HTTP/1.1 200 OK\\r\\n\\r\\n</response>\n"
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "bad_status.xml"
        xml_file.write_text(xml_content)
        requests = parse_burp_xml(xml_file)
        assert len(requests) == 1
        assert requests[0].status_code == 0

    def test_handles_empty_status_code(self, tmp_path: Path) -> None:
        xml_content = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.0.0">\n'
            "  <item>\n"
            "    <url>https://example.com/</url>\n"
            "    <host>example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path>/</path>\n"
            '    <request base64="false">'
            "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
            "</request>\n"
            "    <status></status>\n"
            '    <response base64="false">'
            "HTTP/1.1 200 OK\\r\\n\\r\\n</response>\n"
            "  </item>\n"
            "</items>\n"
        )
        xml_file = tmp_path / "empty_status.xml"
        xml_file.write_text(xml_content)
        requests = parse_burp_xml(xml_file)
        assert len(requests) == 1
        assert requests[0].status_code == 0
