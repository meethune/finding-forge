# Nmap Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `extract_nmap` MCP tool that parses nmap XML output via `python-libnmap` and returns structured per-service results filtered to target scope.

**Architecture:** New `finding_forge.nmap` module with three public functions mirroring the Burp parser pattern (parse, filter, extract). Two new Pydantic models (`NmapScriptResult`, `NmapService`) in `schemas.py`. One new MCP tool registered in `server.py`.

**Tech Stack:** python-libnmap (uses defusedxml internally), Pydantic v2, FastMCP

---

### Task 1: Add dependency and models

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/finding_forge/models/schemas.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_models.py` at the end of the file:

```python
class TestNmapScriptResult:
    def test_construction(self) -> None:
        script = NmapScriptResult(script_id="http-title", output="Test Page")
        assert script.script_id == "http-title"
        assert script.output == "Test Page"

    def test_serialization_roundtrip(self) -> None:
        script = NmapScriptResult(script_id="ssl-cert", output="Subject: CN=example.com")
        data = script.model_dump(mode="json")
        reconstructed = NmapScriptResult.model_validate(data)
        assert reconstructed == script


class TestNmapService:
    def test_minimal_construction(self) -> None:
        svc = NmapService(
            host="10.0.0.1",
            hostname="",
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            version="",
            os_match="",
        )
        assert svc.host == "10.0.0.1"
        assert svc.port == 22
        assert svc.scripts == []

    def test_full_construction(self) -> None:
        svc = NmapService(
            host="10.0.0.1",
            hostname="web.example.com",
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            version="Apache httpd 2.4.52",
            os_match="Linux 5.4",
            scripts=[
                NmapScriptResult(script_id="ssl-cert", output="Subject: CN=web.example.com"),
            ],
        )
        assert svc.hostname == "web.example.com"
        assert svc.version == "Apache httpd 2.4.52"
        assert svc.os_match == "Linux 5.4"
        assert len(svc.scripts) == 1
        assert svc.scripts[0].script_id == "ssl-cert"

    def test_serialization_roundtrip(self) -> None:
        svc = NmapService(
            host="10.0.0.1",
            hostname="web.example.com",
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            version="Apache httpd 2.4.52",
            os_match="Linux 5.4",
            scripts=[NmapScriptResult(script_id="http-title", output="Test")],
        )
        data = svc.model_dump(mode="json")
        reconstructed = NmapService.model_validate(data)
        assert reconstructed == svc
```

Also add `NmapScriptResult` and `NmapService` to the import at the top of `tests/test_models.py`:

```python
from finding_forge.models.schemas import (
    BurpRequest,
    EngagementSession,
    Evidence,
    Finding,
    FindingSeverity,
    FindingTemplate,
    NmapScriptResult,
    NmapService,
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_models.py::TestNmapScriptResult tests/test_models.py::TestNmapService -v`
Expected: ImportError — `NmapScriptResult` and `NmapService` don't exist yet.

- [ ] **Step 3: Add python-libnmap dependency**

In `pyproject.toml`, add `"python-libnmap>=0.7"` to the `dependencies` list (after `"defusedxml>=0.7"`).

Add a mypy override (after the existing `defusedxml` override):

```toml
[[tool.mypy.overrides]]
module = "libnmap.*"
ignore_missing_imports = true
```

Run: `UV_CACHE_DIR=/private/tmp/claude-501/uv-cache uv sync`

- [ ] **Step 4: Add models to schemas.py**

Add the following after the `BurpRequest` class (before `Evidence`) in `src/finding_forge/models/schemas.py`:

```python
class NmapScriptResult(BaseModel):
    """A single NSE script result from an nmap scan."""

    script_id: str
    output: str


class NmapService(BaseModel):
    """A single service detected on a host:port by nmap."""

    host: str
    hostname: str
    port: int
    protocol: str
    state: str
    service: str
    version: str
    os_match: str
    scripts: list[NmapScriptResult] = Field(default_factory=list)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_models.py::TestNmapScriptResult tests/test_models.py::TestNmapService -v`
Expected: All 5 tests PASS.

Run: `ruff check src/finding_forge/models/schemas.py tests/test_models.py && mypy --strict`
Expected: Clean.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock src/finding_forge/models/schemas.py tests/test_models.py
git commit -m "feat: add NmapService and NmapScriptResult models"
```

---

### Task 2: Create nmap extraction module with tests

**Files:**
- Create: `src/finding_forge/nmap/__init__.py`
- Create: `src/finding_forge/nmap/extract.py`
- Create: `tests/fixtures/sample_nmap_scan.xml`
- Create: `tests/test_nmap.py`

- [ ] **Step 1: Create the test fixture**

Create `tests/fixtures/sample_nmap_scan.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -O -sC 10.0.0.1 10.0.0.2" start="1717632000" startstr="Mon Jun  3 12:00:00 2026" version="7.94" xmloutputversion="1.05">
<host starttime="1717632001" endtime="1717632010">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="web.example.com" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.52" method="probed" conf="10"/><script id="http-title" output="Test Page"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Apache httpd" version="2.4.52" tunnel="ssl" method="probed" conf="10"/><script id="ssl-cert" output="Subject: CN=web.example.com"/></port>
    <port protocol="tcp" portid="3306"><state state="filtered" reason="no-response"/><service name="mysql" method="table" conf="3"/></port>
  </ports>
  <os><osmatch name="Linux 5.4" accuracy="95" line="1234"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"/></osmatch></os>
</host>
<host starttime="1717632001" endtime="1717632010">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.2" addrtype="ipv4"/>
  <hostnames/>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="7.6p1" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http-proxy" product="Squid" version="4.13" method="probed" conf="10"/></port>
  </ports>
</host>
<runstats><finished time="1717632020" elapsed="20"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>
```

This fixture has:
- 2 hosts: `10.0.0.1` (hostname `web.example.com`, OS detection) and `10.0.0.2` (no hostname, no OS)
- 6 total services across both hosts
- Mixed states: 5 open, 1 filtered
- NSE scripts on ports 80 and 443 of host 1
- OS fingerprint on host 1 only

- [ ] **Step 2: Write all the failing tests**

Create `tests/test_nmap.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_nmap.py -v`
Expected: ImportError — `finding_forge.nmap.extract` does not exist.

- [ ] **Step 4: Create the nmap module**

Create `src/finding_forge/nmap/__init__.py` (empty file).

Create `src/finding_forge/nmap/extract.py`:

```python
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
    return [
        s for s in services if s.host in host_set or s.hostname in host_set
    ]


def extract_nmap_data(
    xml_path: Path,
    target_hosts: list[str],
) -> list[NmapService]:
    """Parse nmap XML, filter to scope, and return structured services.

    Filters by host before extracting service details to avoid
    wasted work on out-of-scope hosts.
    """
    if not xml_path.exists():
        msg = f"Nmap XML file not found: {xml_path}"
        raise FileNotFoundError(msg)

    host_set = set(target_hosts)
    report = NmapParser.parse_fromfile(str(xml_path))

    services: list[NmapService] = []
    for host in report.hosts:
        hostname = host.hostnames[0] if host.hostnames else ""
        if host.address not in host_set and hostname not in host_set:
            continue

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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_nmap.py -v`
Expected: All 17 tests PASS.

Run: `ruff check src/finding_forge/nmap/ tests/test_nmap.py && ruff format --check src/finding_forge/nmap/ tests/test_nmap.py && mypy --strict`
Expected: Clean.

- [ ] **Step 6: Commit**

```bash
git add src/finding_forge/nmap/ tests/test_nmap.py tests/fixtures/sample_nmap_scan.xml
git commit -m "feat: add nmap XML parser with scope filtering"
```

---

### Task 3: Register MCP tool and update server

**Files:**
- Modify: `src/finding_forge/server.py`
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server.py`. First update the `TestServerToolsRegistered` test to expect the new tool:

```python
# In TestServerToolsRegistered.test_all_tools_registered, add:
assert "extract_nmap" in tool_names
```

Then add a new test class after `TestExtractBurpTool`:

```python
class TestExtractNmapTool:
    async def test_extracts_nmap_data(
        self, templates_dir: Path, tmp_path: Path
    ) -> None:
        nmap_xml = tmp_path / "scan.xml"
        nmap_xml.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sV 10.0.0.1"'
            ' start="1717632000" startstr="Mon Jun  3 12:00:00 2026"'
            ' version="7.94" xmloutputversion="1.05">\n'
            '<host starttime="1717632001" endtime="1717632010">\n'
            '  <status state="up" reason="syn-ack"/>\n'
            '  <address addr="10.0.0.1" addrtype="ipv4"/>\n'
            "  <hostnames/>\n"
            "  <ports>\n"
            '    <port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="ssh" product="OpenSSH" version="8.9p1"'
            ' method="probed" conf="10"/></port>\n'
            "  </ports>\n"
            "</host>\n"
            "<runstats>"
            '<finished time="1717632020" elapsed="20"/>'
            '<hosts up="1" down="0" total="1"/>'
            "</runstats>\n"
            "</nmaprun>\n"
        )
        server = create_server(templates_dir)
        result = await server.call_tool(
            "extract_nmap",
            {
                "xml_path": str(nmap_xml),
                "target_hosts": ["10.0.0.1"],
            },
        )
        content, _is_error = result
        text = content[0].text  # type: ignore[union-attr]
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["host"] == "10.0.0.1"
        assert data[0]["port"] == 22
        assert data[0]["service"] == "ssh"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server.py::TestServerToolsRegistered tests/test_server.py::TestExtractNmapTool -v`
Expected: FAIL — `extract_nmap` not registered.

- [ ] **Step 3: Register the MCP tool**

In `src/finding_forge/server.py`, add the import at the top (after the `extract_burp_data` import):

```python
from finding_forge.nmap.extract import extract_nmap_data
```

Add the tool inside `create_server()`, after the `extract_burp` tool:

```python
    @server.tool()
    def extract_nmap(xml_path: str, target_hosts: list[str]) -> str:
        """Parse nmap XML output, filter to target scope."""
        results = extract_nmap_data(Path(xml_path), target_hosts)
        return _dump_models(results)
```

Update the server instructions string to mention nmap. In the tool workflow section, after the `extract_burp` line, add:

```
"1b. `extract_nmap` — parse nmap XML, filter to target "
"scope, returns structured host/port/service data\n"
```

Also update the opening sentence to mention nmap:

```
"Operators capture evidence during testing (Burp Suite "
"exports, nmap scans, screenshots, notes) and use these "
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_server.py::TestServerToolsRegistered tests/test_server.py::TestExtractNmapTool -v`
Expected: All tests PASS.

Run: `pytest tests/ -v --tb=short` (full suite)
Expected: All tests PASS.

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy --strict`
Expected: Clean.

- [ ] **Step 5: Commit**

```bash
git add src/finding_forge/server.py tests/test_server.py
git commit -m "feat: register extract_nmap MCP tool"
```

---

### Task 4: Update documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update CLAUDE.md**

In the Architecture section, add `nmap/extract.py` to the core library diagram:

```
Core Library                          Wrappers
──────────────────────────────    ─────────────────────────
models/schemas.py (Pydantic)      server.py  (MCP server)
burp/extract.py                   cli.py     (Click CLI)
nmap/extract.py
evidence/capture.py
export/formatters.py
templates/library.py
```

Add a new numbered section after "1. **Burp Extraction**":

```
2. **Nmap Extraction** (`finding_forge.nmap`) — Parses nmap XML scan output via `python-libnmap`, filters to target scope, extracts per-service results with NSE script output.
```

Renumber the remaining sections (3-6).

In the MCP Tools list, add after `extract_burp`:

```
- `extract_nmap` — Parse nmap XML output, filter to target scope
```

- [ ] **Step 2: Update CHANGELOG.md**

Add under the `## Unreleased` section (create it if it doesn't exist, above `## 1.1.1`):

```markdown
## Unreleased

### Added

- `extract_nmap` MCP tool — parses nmap XML output via `python-libnmap`, returns per-service results with host, port, protocol, state, service name, version banner, OS match, and NSE script output, filtered to target scope
- `NmapService` and `NmapScriptResult` Pydantic models for structured nmap data
- `python-libnmap>=0.7` dependency (uses `defusedxml` internally)
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md CHANGELOG.md
git commit -m "docs: add nmap parser to architecture docs and changelog"
```

---

### Task 5: Final verification and PR

- [ ] **Step 1: Run full verification**

```bash
pytest tests/ -v
ruff check src/ tests/
ruff format --check src/ tests/
mypy --strict
```

Expected: All tests pass, no lint/type errors.

- [ ] **Step 2: Push and create PR**

```bash
git push -u origin feat/nmap-parser
```

```bash
gh pr create --title "feat: add nmap XML output parsing tool" --body "$(cat <<'PREOF'
## Summary

- Add `extract_nmap` MCP tool that parses nmap XML output via `python-libnmap` and returns structured per-service results filtered to target scope
- New `NmapService` and `NmapScriptResult` Pydantic models
- Mirrors existing `extract_burp` pattern: parse → filter → extract
- NSE script output included per service
- Scope filtering matches on both IP address and resolved hostname

## Test plan

- [ ] `TestParseNmapXml` — 12 tests covering parsing, field extraction, NSE scripts, error handling
- [ ] `TestFilterByScope` — 5 tests covering IP/hostname filtering, edge cases
- [ ] `TestExtractNmapData` — 2 tests for end-to-end combined operation
- [ ] `TestNmapService` / `TestNmapScriptResult` — 5 model tests
- [ ] `TestExtractNmapTool` — MCP tool integration test
- [ ] Full suite passes, ruff/mypy clean

Closes #3
PREOF
)"
```
