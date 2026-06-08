# Nmap XML Parser — Design Spec

## Purpose

Add an `extract_nmap` MCP tool that parses nmap XML output and returns structured per-service results, filtered to target scope. Mirrors the existing `extract_burp` tool pattern. Uses `python-libnmap` for XML parsing (which already uses `defusedxml` internally).

Closes #3.

## Data Model

Two new Pydantic models in `src/finding_forge/models/schemas.py`:

```python
class NmapScriptResult(BaseModel):
    """A single NSE script result from an nmap scan."""
    script_id: str
    output: str

class NmapService(BaseModel):
    """A single service detected on a host:port by nmap."""
    host: str              # IP address
    hostname: str          # Resolved hostname (empty if none)
    port: int
    protocol: str          # "tcp" or "udp"
    state: str             # "open", "closed", "filtered"
    service: str           # Service name (e.g., "http", "ssh")
    version: str           # Version string (e.g., "Apache httpd 2.4.41")
    os_match: str          # Best OS match (empty if unavailable)
    scripts: list[NmapScriptResult] = Field(default_factory=list)
```

Granularity is per host:port/service combination. One `NmapService` per detected port, analogous to one `BurpRequest` per HTTP request/response pair.

## Module Structure

New module at `src/finding_forge/nmap/`:

```
src/finding_forge/nmap/
    __init__.py          # empty
    extract.py           # parsing logic
```

### Public API (`extract.py`)

Three functions mirroring the Burp module:

1. **`parse_nmap_xml(xml_path: Path) -> list[NmapService]`** — Parse all services from nmap XML. Raises `FileNotFoundError` if file missing. Uses `python-libnmap` (`NmapParser.parse_fromfile`).

2. **`filter_by_scope(services: list[NmapService], target_hosts: list[str]) -> list[NmapService]`** — Filter services to those matching target hosts. Matches on both `host` (IP) and `hostname` (resolved name).

3. **`extract_nmap_data(xml_path: Path, target_hosts: list[str]) -> list[NmapService]`** — Combined parse + filter. Filters during iteration to skip out-of-scope hosts before extracting service details.

### Adapter Logic

Convert libnmap objects to our Pydantic model:

- `NmapHost.address` → `host`
- `NmapHost.hostnames` (first entry or empty) → `hostname`
- `NmapHost.os_match_probabilities()` (best match or empty) → `os_match`
- `NmapService.port` → `port`
- `NmapService.protocol` → `protocol`
- `NmapService.state` → `state`
- `NmapService.service` → `service`
- `NmapService.banner` → `version`
- `NmapService.scripts_results` → `scripts` (list of `NmapScriptResult`)

## MCP Tool

Register in `server.py` following the `extract_burp` pattern:

```python
@server.tool()
def extract_nmap(xml_path: str, target_hosts: list[str]) -> str:
    """Parse nmap XML output, filter to target scope."""
    results = extract_nmap_data(Path(xml_path), target_hosts)
    return _dump_models(results)
```

Add to server instructions alongside `extract_burp`.

## Scope Filtering

The `target_hosts` filter matches on both IP address (`host` field) and resolved hostname (`hostname` field). If the operator passes `["10.0.0.1"]` or `["web.example.com"]`, either should match a service on that host.

## Error Handling

- Missing file → `FileNotFoundError` (checked before calling libnmap)
- Malformed XML → libnmap raises `NmapParserException`; let it propagate
- Services with any state (open, closed, filtered) → included by default
- Missing version/OS/hostname → empty string defaults

## Dependencies

- Add `python-libnmap>=0.7` to `pyproject.toml` dependencies
- Add mypy override for `libnmap` (no type stubs available)

## Test Plan

### Fixture

`tests/fixtures/sample_nmap_scan.xml` — Synthetic nmap XML containing:
- 2 hosts: `10.0.0.1` (hostname `web.example.com`) and `10.0.0.2` (no hostname)
- Mixed ports: 22/tcp open (SSH), 80/tcp open (HTTP), 443/tcp open (HTTPS), 3306/tcp filtered
- NSE scripts on at least one service (e.g., `ssl-cert`, `http-title`)
- OS detection result on one host

### Test Classes

**`tests/test_nmap.py`:**

- `TestParseNmapXml` — parses fixture, correct service count, extracts host/port/service/version, extracts NSE scripts, missing file raises, malformed XML raises
- `TestFilterByScope` — filters by IP, filters by hostname, multiple targets, empty scope returns empty
- `TestExtractNmapData` — end-to-end combined operation, empty scope match

**`tests/test_server.py`:**

- `TestExtractNmapTool` — tool returns JSON, filters to scope

## Documentation Updates

- `CLAUDE.md` — Add `extract_nmap` to MCP Tools list, add nmap module to architecture description
- `CHANGELOG.md` — Add entry under Unreleased
- Server instructions in `server.py` — Add `extract_nmap` description
