# F5 XC WAAP Troubleshooting Tool — Reference Guide

Detailed technical documentation for the xc-troubleshooting tool. For a quick-start guide, see the [README](../README.md).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
  - [Tenant & Auth](#tenant--auth)
  - [Search Parameters](#search-parameters)
  - [Report Settings](#report-settings)
  - [Environment Variables](#environment-variables)
- [CLI Options](#cli-options)
- [How the Tool Works](#how-the-tool-works)
  - [Pipeline Overview](#pipeline-overview)
  - [Query Builder](#query-builder)
  - [Parsers](#parsers)
  - [Verdict & Metrics](#verdict--metrics)
  - [Detectors & Findings](#detectors--findings)
- [Report Format](#report-format)
  - [HTML Report](#html-report)
  - [Traffic Flow Diagram](#traffic-flow-diagram)
  - [Report Sections](#report-sections)
  - [Verdict Types](#verdict-types)
- [Public Research](#public-research)
- [Input Validation & Security](#input-validation--security)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

---

## Project Structure

```
xc-troubleshooting/
├── bin/
│   └── run-troubleshoot.sh          # Run the troubleshooter
├── config/
│   ├── config.yaml                  # Main config (git-ignored)
│   └── config.yaml.example          # Example — copy and edit
├── docs/
│   └── REFERENCE.md                 # This file
├── reports/                         # Output directory for generated reports
├── src/
│   ├── xc_troubleshoot.py           # Legacy entry point (backward-compatible shim)
│   ├── html_report.py               # Legacy import shim for html report
│   └── xc_troubleshoot/             # Main package
│       ├── __init__.py              # v2.0.0, module exports
│       ├── __main__.py              # python -m xc_troubleshoot entry point
│       ├── cli.py                   # CLI argument parsing & main()
│       ├── config.py                # YAML + env var config loader & validation
│       ├── validation.py            # Input sanitization (LogQL, Markdown, XSS)
│       ├── client.py                # F5 XC API client with retry/backoff
│       ├── models.py                # TypedDicts + FieldDef schema definitions
│       ├── parsers.py               # Extract structured summaries from raw API data
│       ├── analysis.py              # Verdict computation & metrics aggregation
│       ├── hints.py                 # Pluggable detector pattern for findings
│       ├── orchestrator.py          # Pipeline orchestrator: query → parse → analyse → render → save
│       ├── lb_config.py             # HTTP LB config parser, user identification resolver
│       ├── traffic_flow.py          # Traffic flow analysis (path type + latency)
│       ├── reports/                 # Report renderers
│       │   ├── __init__.py
│       │   ├── base.py              # ReportData container (computed fields via .build())
│       │   ├── html.py              # Self-contained HTML report renderer
│       │   ├── save.py              # File I/O with sanitized filenames
│       │   ├── _css.py              # Embedded CSS for HTML reports
│       │   ├── _services_svg.py     # Inline SVG renderer for security services pipeline
│       │   └── _traffic_svg.py      # Inline SVG renderer for traffic flow diagram
│       └── research/                # Optional public research feature
│           ├── __init__.py
│           ├── queries.py           # Derive search queries from events
│           ├── google.py            # Google search client (scoped to F5 sites)
│           └── formatters.py        # Format research results for reports
├── requirements.txt
└── README.md
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `cli.py` | Thin shell — parses CLI arguments, loads config, merges overrides, delegates to the orchestrator |
| `config.py` | Load and validate YAML config, environment variable overrides, typed dataclasses (`AppConfig`, `SearchParams`, `ReportConfig`) |
| `validation.py` | Input sanitization — prevents LogQL query injection, Markdown injection, and XSS in report output |
| `client.py` | F5 XC API client with automatic retry/backoff on transient failures (429, 5xx), query builder for LogQL-style filters |
| `models.py` | Field schemas (`FieldDef`) and TypedDicts (`SecurityEvent`, `AccessLog`) — drive parsing and rendering from a single source |
| `parsers.py` | Extract structured event/log summaries from raw API JSON using the field schemas |
| `analysis.py` | Compute verdict (BLOCKED / MONITORED / ALLOWED / NO DATA / INFO), aggregate metrics, generate search mode labels |
| `hints.py` | Pluggable detector pattern — six detectors that inspect events/logs and return structured findings |
| `orchestrator.py` | Full pipeline: query APIs → parse → fetch LB config → enrich user ID → analyse → render → save. Decoupled from CLI for testability. |
| `lb_config.py` | Parse HTTP LB config to detect enabled security services (WAF, Bot, DDoS, etc.). Resolve user identification policy details from API + runtime event data. |
| `traffic_flow.py` | Traffic flow analysis — classify request path (Internet→RE→App, Internet→RE→CE→App, Internal→CE→App), aggregate latency across multiple entries |
| `reports/base.py` | `ReportData` container — holds all data needed by renderers, computes derived fields via `.build()` |
| `reports/html.py` | Self-contained HTML report — embedded CSS, traffic flow diagram, services pipeline, action/code badges, collapsible detail sections |
| `reports/_services_svg.py` | Inline SVG renderer for the security services pipeline diagram (enabled/disabled services, user identification details) |
| `reports/_traffic_svg.py` | Inline SVG renderer for the traffic flow diagram — icons, latency pills, hover tooltips |
| `reports/save.py` | File I/O — sanitized filenames, timestamped output |
| `research/queries.py` | Derive Google search queries from security event names, response codes, and access log flags |
| `research/google.py` | Scrape Google results scoped to F5 DevCentral, cloud docs, and MyF5 |
| `research/formatters.py` | Format research results as collapsible Markdown sections |

---

## Installation

For a quick platform-specific setup guide, see the [README](../README.md#1-install-dependencies).

### Prerequisites

- Python 3.9+
- An F5 Distributed Cloud tenant with API access
- An API Token (not a certificate — this tool uses token-based auth)

### Install Steps

All commands assume you are in the project directory:

```bash
cd tools/xc-troubleshooting
```

A virtual environment is recommended:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate an API Token

1. Log into your F5 XC Console
2. Navigate to **Administration → Credentials → API Credentials**
3. Click **Create Credentials**
4. Select **API Token** as the credential type
5. Set an expiry and click **Generate**
6. Copy the token value

### Verify Installation

```bash
python3 --version    # must be 3.9+
source venv/bin/activate
chmod +x bin/run-troubleshoot.sh
./bin/run-troubleshoot.sh --help
```

If you see `ModuleNotFoundError: No module named 'requests'` or similar, the dependencies are not installed. Re-run `pip install -r requirements.txt`.

---

## Configuration Reference

Copy the example file first:

```bash
cp config/config.yaml.example config/config.yaml
```

> **Security note:** `config/config.yaml` is git-ignored. Never commit your API token. For environments where files are risky, use `XC_API_TOKEN` as an env var instead — it takes precedence over the YAML value.

### Tenant & Auth

```yaml
tenant:
  name: "acmecorp"                    # the part before .console.ves.volterra.io

auth:
  api_token: "your-actual-api-token"  # from F5 XC Console
```

### Search Parameters

```yaml
request:
  req_id: ""                          # request ID to search for
  src_ip: ""                          # source IP to search for
  fqdn: ""                            # FQDN / hostname to filter by
  load_balancer: ""                   # load balancer name (optional narrowing filter)
  search_window_hours: 24             # how far back to search (in hours)
```

At least one of `req_id`, `src_ip`, or `fqdn` must be provided (via config or CLI).

| Parameter | Config key | CLI flag | Description |
|-----------|-----------|----------|-------------|
| Request ID | `request.req_id` | `--req-id, -r` | UUID or identifier from `X-Request-Id` header |
| Source IP | `request.src_ip` | `--src-ip, -s` | Client IP address (IPv4 or IPv6) |
| FQDN | `request.fqdn` | `--fqdn, -d` | Hostname / authority (e.g. `api.example.com`) |
| Load Balancer | `request.load_balancer` | `--load-balancer, -l` | Load balancer name — uses regex contains match on `vh_name` |
| Search Window | `request.search_window_hours` | `--hours` | Time window in hours, counting backwards from now (default: 24) |

**Namespace** is not configured in YAML — it defaults to `system` (all namespaces) and can only be overridden via `--namespace / -n` on the CLI.

**CLI flags always override config values** when both are provided.

### Report Settings

```yaml
report:
  output_dir: "reports"               # relative to project root, or absolute path
  format: "html"
```

| Key | Default | Description |
|-----|---------|-------------|
| `output_dir` | `reports` | Directory for generated reports. Relative paths resolve from the project root. |
| `format` | `html` | Report output format. Only `html` is supported. |

### Environment Variables

Environment variables take precedence over YAML values for secrets:

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `XC_API_TOKEN` | `auth.api_token` | API token — recommended for CI/CD and shared environments |
| `XC_TENANT` | `tenant.name` | Tenant name |

---

## CLI Options

The recommended way to run the tool is via the shell wrapper:

```bash
./bin/run-troubleshoot.sh --req-id "abc123"
```

The wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

Alternatively, you can run it directly as a Python module or via the legacy entry point:

```bash
# As a module
PYTHONPATH=src python3 -m xc_troubleshoot --req-id "abc123"

# Legacy entry point (backward-compatible)
python3 src/xc_troubleshoot.py --req-id "abc123"
```

```
Options:
  --config, -c         Path to YAML config file (default: config/config.yaml)

Search criteria (at least one required):
  --req-id, -r         Request ID (overrides config)
  --src-ip, -s         Source IP (overrides config)
  --fqdn, -d           FQDN / hostname (overrides config)
  --load-balancer, -l  Load balancer name (overrides config)

  --namespace, -n      Namespace to query (default: "system" = all namespaces)
  --format, -f         Report format (default: html)
  --hours              Search window in hours (default: 24)
  --limit              Max events per query (default: 50)
  --output-dir, -o     Output directory for reports (overrides config)

Optional features:
  --research           Search F5 public docs & community for known issues
  --verbose, -v        Enable verbose (debug) logging
```

---

## How the Tool Works

### Pipeline Overview

The tool follows a linear pipeline. All steps are orchestrated by `orchestrator.py`:

```
CLI  →  Config  →  Query Builder  →  API Client  →  Parsers  →  Analysis  →  Renderers  →  Save
```

1. **Config** — load YAML, merge env vars, merge CLI overrides, validate all inputs
2. **Query** — build a LogQL-style filter string, query both API endpoints (security events + access logs)
3. **Parse** — extract structured event/log summaries from raw API JSON using field schemas
4. **Analyse** — compute verdict, aggregate metrics, run detectors to generate findings
5. **Render** — generate report content in the selected format(s)
6. **Save** — write report files to disk with sanitized, timestamped filenames

Both API queries (security events and access logs) are executed independently. If one fails, the other still runs and the failure is captured in the report as an API error banner.

### Query Builder

The query builder (`client.py:build_query`) constructs a LogQL-style filter string from the search parameters:

```python
# Single filter
{req_id="abc12345-6789-def0-1234-567890abcdef"}

# Combined filters
{src_ip="203.0.113.42", authority="api.example.com"}

# With load balancer (regex contains match)
{src_ip="203.0.113.42", vh_name=~".*my-app-lb.*"}
```

All values are validated before embedding to prevent query injection. The load balancer name uses a regex contains match (`=~`) while all other fields use exact match (`=`).

### Parsers

Parsers (`parsers.py`) extract structured summaries from raw API JSON. They are **schema-driven** — the field definitions in `models.py` (`SECURITY_EVENT_FIELDS`, `ACCESS_LOG_FIELDS`) define:

- The internal key name
- The display label
- The API response key (with optional fallback key)
- The default value
- Whether the field is extracted from the nested `policy_hits` structure

This means adding a new field requires only a single `FieldDef` entry — parsers and all report renderers pick it up automatically.

### Verdict & Metrics

The analysis module (`analysis.py`) computes:

**Verdict** — a single overall assessment based on event actions:

| Verdict | Condition |
|---------|-----------|
| **BLOCKED** | Any security event has action containing "block" or "deny" |
| **MONITORED** | Security events exist with action "report" but none blocked |
| **ALLOWED** | Access logs exist but no security events |
| **NO DATA** | Neither security events nor access logs found |
| **INFO** | Events found but none match the above categories |

**Metrics** — aggregate counts and distributions:

- Total security events and access logs
- Blocked / reported counts
- Unique source IPs, hosts, paths, and request IDs
- Response code distribution
- Security event type breakdown

### Detectors & Findings

The hints module (`hints.py`) uses a **pluggable detector pattern**. Each detector is a standalone class that inspects events/logs and returns zero or more structured findings.

| Detector | What it detects |
|----------|----------------|
| `NoDataDetector` | No events or logs found — suggests widening search |
| `SecurityEventDetector` | One finding per unique (event_name, action) pair — merges related symptoms |
| `OASDetector` | OpenAPI / OAS validation failures — paths not in spec |
| `JWTDetector` | JWT validation issues — missing, invalid, or expired tokens |
| `BotDetector` | Bot classification findings |
| `ResponseFlagDetector` | Envoy response flags from access logs (UH, UF, NR, UT, etc.) |
| `NoIssuesDetector` | Positive confirmation when no security issues are detected |

Each finding has:

- **Severity** — `error`, `warning`, or `info`
- **Title** — short headline (e.g. "Blocked: waf_sec_event (3x)")
- **Summary** — one-liner explanation
- **Details** — contextual information (event type, action, response code, policy)
- **Recommendations** — actionable next steps

Findings are deduplicated by title (OAS/JWT findings from the specialized detectors take priority over generic `SecurityEventDetector` duplicates) and sorted by severity (errors first).

**Adding a new detector:** Create a class that inherits from `Detector`, implement `detect()`, and add an instance to the `DETECTORS` list in `hints.py`. No other code changes are needed.

---

## Report Format

Reports are saved to the `reports/` directory (configurable). Filenames follow the pattern:

```
report_<search_label>_<timestamp>.<ext>
```

The search label is built from the search parameters (request ID, source IP, FQDN, load balancer name) with unsafe characters sanitized. Examples:

```
report_52a5ec46-59b8-45f_20260226_143022.html
report_ip_203.0.113.42_20260226_143022.html
report_ip_203.0.113.42_fqdn_api.example.com_20260226_143022.html
```

### HTML Report

Self-contained single-file report with embedded CSS. No external dependencies — can be opened directly in a browser or attached to an email/ticket.

Features:

- **Traffic flow diagram** — inline SVG showing the request path with per-segment latency
- **Color-coded verdict banner** — red (blocked), yellow (monitored), green (allowed), grey (no data), blue (info)
- **Metric cards** — security event counts, blocked/reported, access logs, unique IPs, unique requests
- **Action badges** — colored inline badges for actions (block=red, report=yellow, allow=green)
- **Response code badges** — colored by class (2xx=green, 3xx=blue, 4xx=yellow, 5xx=red)
- **Finding cards** — collapsible cards with severity icons, WAF signature details, threat campaigns, and recommendations
- **Collapsible detail tables** — per-event and per-log detail tables driven by field schemas
- **Copy-to-clipboard** — raw JSON sections have a copy button
- **Print-friendly** — includes `@media print` styles

All user-controlled values are HTML-escaped via `html.escape()`.

### Traffic Flow Diagram

The report includes an inline SVG traffic flow diagram showing the network path the request took. Three path types are detected automatically:

| Path Type | When | Nodes |
|-----------|------|-------|
| **Internet → RE → App** | Client on public internet, origin via internet (default) | Client → RE → App |
| **Internet → RE → CE → App** | Client on public internet, origin behind Customer Edge | Client → RE → CE → App |
| **Internal → CE → App** | Internal client originating from a CE site | Client → CE → App |

Detection is based on the `src` field (public vs private) and `dst_site` (NOT-APPLICABLE = no CE involved).

**Per-node info:**
- Client: source IP, geo (city/country), ASN
- RE: site name, FQDN
- CE: destination site
- App: upstream cluster or destination IP; "Blocked by WAF" indicator if blocked

**Per-segment info:**
- TLS version label
- Latency (from raw access log timing fields)

**Multi-request aggregation** (search by IP or FQDN):
- Latencies are averaged across all entries; hover tooltips show min/max/sample count
- Nodes show aggregated info ("3 unique IPs", "2 RE sites")
- A yellow "Aggregated from N requests" banner appears at the top of the diagram
- If some requests were blocked: "2/5 blocked by WAF"

### Report Sections

The HTML report includes the following sections:

| Section | Description |
|---------|-------------|
| **Header** | Search mode, filters used, tenant, namespace, time window, generation timestamp |
| **Traffic Flow** | SVG diagram of the request path with latency per segment |
| **API Error Banner** | Shown if any API queries failed — warns that the report may be incomplete |
| **Verdict Banner** | Overall assessment: BLOCKED / MONITORED / ALLOWED / NO DATA / INFO |
| **Management Summary** | Event counts, response code distribution, security event breakdown, unique IPs/requests |
| **Key Findings** | Context-aware troubleshooting hints from the detector pipeline |
| **Services Enabled** | SVG pipeline diagram of all security services on the HTTP LB, collapsible detail tables (enabled/disabled services, mode, policy names, user identification details) |
| **Detailed Security Events** | Collapsible per-event details (all fields from the schema, WAF rule hits as JSON) |
| **Detailed Access Logs** | Collapsible per-log details (timing, upstream info, response flags, policy results) |
| **Public Research** | *(optional, `--research`)* Links to F5 docs, DevCentral, and MyF5 articles |
| **Raw JSON Data** | Collapsible sections with the full API response for both endpoints |

### Verdict Types

| Verdict | CSS class | Color | Meaning |
|---------|-----------|-------|---------|
| **BLOCKED** | `blocked` | Red | One or more requests blocked by security policy |
| **MONITORED** | `monitored` | Yellow | Security events reported but not blocked (WAF in report/monitor mode) |
| **ALLOWED** | `allowed` | Green | Access logs exist but no security events — request passed cleanly |
| **NO DATA** | `nodata` | Grey | No events or logs found for the search criteria |
| **INFO** | `info` | Blue | Events found — review details for assessment |

---

## Public Research

When `--research` is passed, the tool searches F5 public documentation for articles related to the detected events.

### How it works

1. **Query derivation** (`research/queries.py`) — builds search queries from:
   - Security event names (e.g. `F5 XC "waf_sec_event"`)
   - Blocked requests with 4xx/5xx response codes
   - JWT-related events
   - OpenAPI validation / fallthrough events
   - Bot classification events
   - Access log response flags

2. **Google search** (`research/google.py`) — scrapes Google results scoped to:
   - `community.f5.com` (F5 DevCentral)
   - `docs.cloud.f5.com` (F5 Cloud Docs)
   - `my.f5.com` (F5 Support / MyF5)

3. **Deduplication** — results are deduplicated by URL across all queries

4. **Rate limiting** — 1-second delay between Google requests to avoid throttling

Results are included in the report as a collapsible section grouped by search query.

---

## Input Validation & Security

The validation module (`validation.py`) enforces strict input sanitization to prevent:

### LogQL Query Injection

All values embedded in API queries are checked against unsafe characters (`"`, `{`, `}`, `\n`, `\r`, `\`). The query builder constructs filter strings using exact-match syntax (`field="value"`), so injecting query operators is prevented.

### Input Format Validation

| Input | Pattern | Description |
|-------|---------|-------------|
| Request ID | `^[\w\-.:]+$` | Alphanumerics, hyphens, dots, colons |
| Source IP | `^[\d.:a-fA-F]+$` | IPv4/IPv6 characters only |
| FQDN | `^[\w.\-]+$` | Hostname labels, max 253 chars |
| Load Balancer | `^[\w.\-]+$` | Alphanumerics, hyphens, underscores, dots, max 256 chars |
| Namespace | `^[\w\-]+$` | Alphanumerics, hyphens, underscores |
| Tenant | `^[\w\-]+$` | Alphanumerics, hyphens, underscores |

### HTML Escaping

User-controlled values in HTML reports are escaped using Python's `html.escape()` to prevent XSS.

### Token Security

- The API token is **never logged** — `AuthConfig.__repr__()` redacts it
- The `XCClient.__repr__()` shows only the first 4 characters
- Environment variable (`XC_API_TOKEN`) is recommended over file-based config for shared environments
- Placeholder values (`REPLACE_WITH_YOUR_API_TOKEN`, `your-api-token`, etc.) are detected and rejected at config load time

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/data/namespaces/{ns}/app_security/events` | POST | Query security events with LogQL-style filter |
| `/api/data/namespaces/{ns}/access_logs` | POST | Query access logs with LogQL-style filter |
| `/api/config/namespaces/{ns}/http_loadbalancers/{name}` | GET | Fetch HTTP Load Balancer configuration (security services) |
| `/api/config/namespaces/{ns}/user_identifications/{name}` | GET | Fetch User Identification policy (identifier rules) |

The two POST endpoints accept the same request body structure:

```json
{
  "namespace": "system",
  "query": "{req_id=\"abc123\"}",
  "start_time": "2026-02-25T14:30:00.000Z",
  "end_time": "2026-02-26T14:30:00.000Z",
  "sort": "DESCENDING",
  "limit": 50
}
```

Authentication: `Authorization: APIToken <token>` header on every request.

### Retry Behavior

The HTTP client retries automatically on transient failures:

| Status Code | Meaning | Retried? |
|-------------|---------|----------|
| 429 | Rate limited | Yes |
| 500 | Internal server error | Yes |
| 502 | Bad gateway | Yes |
| 503 | Service unavailable | Yes |
| 504 | Gateway timeout | Yes |
| Other | Client error / success | No |

Retry strategy: 3 attempts, exponential backoff (1s, 2s, 4s).

---

## Troubleshooting

### Common Errors

| Problem | Solution |
|---------|----------|
| `Config file not found` | Copy `config.yaml.example` to `config.yaml` and fill in your values |
| `Missing or placeholder API token` | Set `XC_API_TOKEN` env var or edit `config.yaml` with a real token |
| `Invalid characters in ...` | Input validation rejected unsafe characters — check the value format |
| `401 Unauthorized` | API token is invalid or expired — regenerate it in F5 XC Console |
| `403 Forbidden` | Token lacks permissions for the namespace — check RBAC settings |
| `No search criteria` | Provide at least `--req-id`, `--src-ip`, or `--fqdn` (via CLI or config) |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |

### No Events Found

| Problem | Solution |
|---------|----------|
| No events for the request ID | Widen `--hours` — the event may be outside the 24h default window |
| No events for the source IP | Try adding `--fqdn` or `--load-balancer` to narrow the search, or widen `--hours` |
| Events exist in UI but not in API | Try `--namespace <specific-ns>` instead of the default `system` (all namespaces) |
| Report shows "API queries failed" | One or both API calls failed — check the error details in the report |

### Report Issues

| Problem | Solution |
|---------|----------|
| Report is empty / "NO DATA" | No events or logs matched the search criteria. Widen the search window or verify the search values. |
| Report shows only access logs | No security violations occurred — the request was allowed. This is expected behavior. |
| HTML report looks broken | The report is self-contained — if CSS is missing, the file may have been truncated. Re-run the tool. |

### Python Environment

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'requests'` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'yaml'` | Run `pip install -r requirements.txt` (installs PyYAML) |
| `SyntaxError` on startup | Python 3.9+ is required. Check with `python3 --version`. |
| Permission denied on `run-troubleshoot.sh` | Run `chmod +x bin/run-troubleshoot.sh` |
| Virtual environment not activated | Run `source venv/bin/activate` before running the tool, or use `./bin/run-troubleshoot.sh` which auto-activates it |
