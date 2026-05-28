"""Burp Suite proxy history XML extraction."""

import base64
import xml.etree.ElementTree as ET
from pathlib import Path

from finding_forge.models.schemas import BurpRequest


def _get_text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text


def _decode_content(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    if child is None or child.text is None:
        return ""
    is_base64 = child.get("base64", "false") == "true"
    if is_base64:
        return base64.b64decode(child.text).decode("utf-8", errors="replace")
    return child.text


def _parse_http_message(
    raw: str,
) -> tuple[dict[str, str], str | None]:
    if not raw:
        return {}, None
    parts = raw.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 and parts[1] else None

    headers: dict[str, str] = {}
    for line in header_block.splitlines()[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value

    return headers, body


def parse_burp_xml(xml_path: Path) -> list[BurpRequest]:
    """Parse a Burp Suite XML proxy history export into BurpRequest objects."""
    if not xml_path.exists():
        msg = f"Burp XML file not found: {xml_path}"
        raise FileNotFoundError(msg)

    tree = ET.parse(xml_path)
    root = tree.getroot()

    requests: list[BurpRequest] = []
    for item in root.findall("item"):
        raw_request = _decode_content(item, "request")
        raw_response = _decode_content(item, "response")

        req_headers, req_body = _parse_http_message(raw_request)
        resp_headers, resp_body = _parse_http_message(raw_response)

        status_text = _get_text(item, "status")

        requests.append(
            BurpRequest(
                url=_get_text(item, "url"),
                method=_get_text(item, "method"),
                host=_get_text(item, "host"),
                path=_get_text(item, "path"),
                request_headers=req_headers,
                request_body=req_body,
                status_code=int(status_text) if status_text else 0,
                response_headers=resp_headers,
                response_body=resp_body,
            )
        )

    return requests


def filter_by_scope(
    requests: list[BurpRequest],
    target_hosts: list[str],
) -> list[BurpRequest]:
    """Filter requests to only those matching target host scope."""
    host_set = set(target_hosts)
    return [r for r in requests if r.host in host_set]


def extract_burp_data(
    xml_path: Path,
    target_hosts: list[str],
) -> list[BurpRequest]:
    """Parse Burp XML, filter to scope, and return structured requests."""
    all_requests = parse_burp_xml(xml_path)
    return filter_by_scope(all_requests, target_hosts)
