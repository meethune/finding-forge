"""Shared test fixtures for finding-forge."""

from pathlib import Path
from textwrap import dedent

import pytest


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
        finding_type: Web
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

        ## Guidance

        Use when error-based or blind SQLi is confirmed.
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
        finding_type: Cloud
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


@pytest.fixture()
def burp_xml(tmp_path: Path) -> Path:
    """Create a sample Burp XML export file."""
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(
        '<?xml version="1.0"?>\n'
        '<items burpVersion="2024.0.0">\n'
        "  <item>\n"
        "    <url><![CDATA[https://app.example.com/login]]></url>\n"
        "    <host>app.example.com</host>\n"
        "    <port>443</port>\n"
        "    <protocol>https</protocol>\n"
        "    <method><![CDATA[POST]]></method>\n"
        "    <path><![CDATA[/login]]></path>\n"
        '    <request base64="false"><![CDATA[POST /login HTTP/1.1\r\n'
        "Host: app.example.com\r\n\r\nuser=admin]]></request>\n"
        "    <status>200</status>\n"
        '    <response base64="false"><![CDATA[HTTP/1.1 200 OK\r\n'
        "Content-Type: text/html\r\n\r\nOK]]></response>\n"
        "  </item>\n"
        "</items>\n"
    )
    return xml_file
