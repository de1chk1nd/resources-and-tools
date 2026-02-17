# F5 XC WAAP Troubleshooting Tool

CLI tool that queries F5 Distributed Cloud (XC) security event logs by **request ID**, **source IP**, **FQDN**, or any combination, and generates a local troubleshooting report.

## What it does

1. Reads configuration (tenant, API token, search criteria) from a YAML config file
2. Queries the F5 XC API for **security events** and **access logs** matching the search criteria
3. Extracts key fields (source IP, WAF action, rule hits, response codes, etc.)
4. Generates a **management summary** with verdict, metrics, and key findings
5. Generates context-aware **troubleshooting hints** (blocked requests, WAF mode, response flags, bot detection)
6. Optionally searches **F5 public documentation & community** for known issues (`--research`)
7. Saves a report locally in **Markdown**, **HTML**, or **JSON** format (or Markdown + HTML combined with `--format all`)

### Search Modes

| Mode | Use case |
|------|----------|
| `--req-id` only | Customer provides a specific request ID |
| `--src-ip` only | Customer only provides their IP address |
| `--fqdn` only | Search all events for a specific hostname |
| `--req-id` + `--src-ip` | Narrow down to a specific request from a specific IP |
| `--src-ip` + `--fqdn` | All events from an IP to a specific hostname |
| any + `--load-balancer` | Further narrow by load balancer name |

You can start with a request ID, then pivot to the source IP to see all events from that client.
Use `--fqdn` and `--load-balancer` as optional filters to narrow results.

## Project Structure

```
xc-troubleshooting/
├── config/
│   ├── config.yaml              # Your local config (git-ignored)
│   └── config.yaml.example      # Example config — copy and edit
├── reports/                     # Generated reports land here
├── src/
│   ├── xc_troubleshoot.py       # Backward-compatible entry point (shim)
│   ├── html_report.py           # Backward-compatible import shim
│   └── xc_troubleshoot/         # Main package
│       ├── __init__.py
│       ├── __main__.py           # python -m xc_troubleshoot entry point
│       ├── cli.py                # CLI argument parsing & orchestration
│       ├── config.py             # YAML config loading & validation
│       ├── client.py             # F5 XC API client & query builder
│       ├── models.py             # TypedDict models & field schemas
│       ├── analysis.py           # Verdict, metrics, shared helpers
│       ├── parsers.py            # Schema-driven API response parsers
│       ├── hints.py              # Context-aware troubleshooting hints
│       ├── research.py           # Public research (F5 docs & community)
│       └── reports/
│           ├── __init__.py
│           ├── base.py           # ReportData container
│           ├── _css.py           # Embedded CSS for HTML reports
│           ├── markdown.py       # Markdown report renderer
│           ├── html.py           # HTML report renderer
│           ├── json_report.py    # JSON report renderer
│           └── save.py           # Report file I/O
├── requirements.txt
├── .gitignore
└── README.md
```

### Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `cli.py` | Argument parsing, logging setup, orchestration |
| `config.py` | Load and validate YAML configuration (raises `ConfigError`) |
| `client.py` | `XCClient` HTTP client + LogQL query builder |
| `models.py` | `TypedDict` models + `FieldDef` schemas for events/logs |
| `analysis.py` | `Verdict`, `ReportMetrics`, `search_mode_label` |
| `parsers.py` | Schema-driven API response parsing (no per-field code) |
| `hints.py` | Context-aware troubleshooting hints engine |
| `research.py` | Google search for F5 public docs & community |
| `reports/base.py` | `ReportData` container — computed once, shared by renderers |
| `reports/_css.py` | Embedded CSS for HTML reports (isolated) |
| `reports/markdown.py` | Markdown renderer (schema-driven field iteration) |
| `reports/html.py` | HTML renderer (schema-driven field iteration) |
| `reports/json_report.py` | JSON renderer |
| `reports/save.py` | Write reports to disk with structured filenames |

## Prerequisites

- Python 3.9+
- An F5 Distributed Cloud tenant with API access
- An API Token (not a certificate — this tool uses token-based auth)

### Generate an API Token

1. Log into your F5 XC Console
2. Navigate to **Administration > Credentials > API Credentials**
3. Click **Create Credentials**
4. Select **API Token** as the credential type
5. Set an expiry and click **Generate**
6. Copy the token value

## Setup

### 1. Clone / enter the project directory

```bash
cd xc-troubleshooting
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Or in a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure

```bash
cp config/config.yaml.example config/config.yaml
```

Edit `config/config.yaml` with your values:

```yaml
tenant:
  name: "acmecorp"

auth:
  api_token: "your-actual-api-token"

request:
  req_id: ""           # can also pass via CLI --req-id
  src_ip: ""           # can also pass via CLI --src-ip
  fqdn: ""             # can also pass via CLI --fqdn
  namespace: "default"
  load_balancer: ""    # can also pass via CLI --load-balancer
  search_window_hours: 24

report:
  output_dir: "reports"
  format: "markdown"   # "markdown", "html", "json", or "all" (md+html)
```

> **Security note:** `config/config.yaml` is git-ignored by default. Never commit your API token.

## Usage

### Invocation

The tool can be run in two ways (both are equivalent):

```bash
# As a module (recommended)
PYTHONPATH=src python3 -m xc_troubleshoot --req-id "abc123"

# Legacy entry point (backward-compatible)
python3 src/xc_troubleshoot.py --req-id "abc123"
```

### Search by request ID

```bash
python3 src/xc_troubleshoot.py --req-id "abc12345-6789-def0-1234-567890abcdef"
```

### Search by source IP

```bash
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42"
```

### Search by FQDN

```bash
python3 src/xc_troubleshoot.py --fqdn "api.example.com"
```

### Combine filters

```bash
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42" --fqdn "api.example.com" --load-balancer "my-app-lb"
```

### Include public research

```bash
python3 src/xc_troubleshoot.py --req-id "abc123" --research
```

### All CLI options

```
Search criteria (at least one required):
  --req-id, -r         Request ID to search for (overrides config)
  --src-ip, -s         Source IP to search for (overrides config)
  --fqdn, -d           FQDN / hostname to filter by (overrides config)
  --load-balancer, -l  Load balancer name to filter by (overrides config)

Options:
  --config, -c     Path to YAML config file (default: config/config.yaml)
  --namespace, -n  Namespace (overrides config)
  --format, -f     Report format: markdown, html, json, or all (overrides config)
  --hours          Search window in hours (overrides config)
  --limit          Max events per query (default: 50)
  --output-dir, -o Output directory for reports (overrides config)

Optional features:
  --research       Search F5 public docs & community for known issues
  --verbose, -v    Enable verbose (debug) logging
```

### Examples

```bash
# Search last 48 hours by IP, output as JSON
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42" --hours 48 --format json

# Generate a customer-ready HTML report
python3 src/xc_troubleshoot.py --req-id "abc123" --format html

# Generate both Markdown and HTML reports at once
python3 src/xc_troubleshoot.py --req-id "abc123" --format all

# Search by FQDN only — all events for a specific hostname
python3 src/xc_troubleshoot.py --fqdn "api.example.com" --hours 24

# Combine: all events from an IP hitting a specific host
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42" --fqdn "api.example.com"

# Narrow by load balancer name
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42" --load-balancer "my-app-lb"

# Include public research for known issues
python3 src/xc_troubleshoot.py --req-id "abc123" --research

# Find a specific request, then pivot to all events from that IP
python3 src/xc_troubleshoot.py --req-id "abc123"
# ... report shows src_ip=203.0.113.42, now get all events from that IP:
python3 src/xc_troubleshoot.py --src-ip "203.0.113.42" --hours 72

# Use a different config file
python3 src/xc_troubleshoot.py --config /path/to/other-config.yaml --req-id "abc123"

# Specify namespace and increase result limit
python3 src/xc_troubleshoot.py --src-ip "10.0.0.1" --namespace "production" --limit 100
```

## Report Output

Reports are saved to the `reports/` directory (configurable). Filenames follow the pattern:

```
report_<search_label>_<timestamp>.<ext>
```

Where `<ext>` is `.md`, `.html`, or `.json` depending on the chosen format.

### Report Formats

| Format | Flag | Description |
|--------|------|-------------|
| **Markdown** | `--format markdown` | Default. Collapsible sections, tables, raw JSON. Good for Git/ticketing systems. |
| **HTML** | `--format html` | Polished, self-contained single-file report with embedded CSS. Customer-ready. Includes verdict banner, metric cards, color-coded badges, and print-friendly layout. |
| **JSON** | `--format json` | Machine-readable. Includes all parsed events, access logs, and raw API data. |
| **All** | `--format all` | Generates both Markdown and HTML reports side by side. |

### Report Contents

Both Markdown and HTML reports include:

- **Header** — search mode, filters used, tenant, namespace, time window
- **Verdict Banner** — BLOCKED / MONITORED / ALLOWED / NO DATA / INFO
- **Management Summary** — event counts, response code distribution, security event breakdown, unique IPs/requests
- **Key Findings** — context-aware troubleshooting hints (blocked requests, WAF mode, response flags, bot detection, JWT issues, OAS validation)
- **Detailed Security Events** — collapsible per-event details (WAF action, policy, rule hits, JWT, OAS, bot classification, geo, TLS fingerprint)
- **Detailed Access Logs** — collapsible per-request details (timing, upstream info, response flags, policy results)
- **Public Research** *(optional, `--research`)* — links to F5 docs, DevCentral, and MyF5 articles matching the events found
- **Raw JSON data** — collapsible sections with the full API response

## Public Research (`--research`)

When enabled, the tool automatically:

1. Derives search terms from the security events (event names, response codes, error patterns)
2. Searches Google scoped to F5 public sources:
   - **F5 DevCentral** (community.f5.com) — community articles, Q&A
   - **F5 Cloud Docs** (docs.cloud.f5.com) — official documentation
   - **F5 MyF5** (my.f5.com) — knowledge base / K-articles
3. Includes results as a collapsed section in the report with titles, links, and snippets

This is disabled by default to keep report generation fast. Add `--research` when you need it.

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /api/data/namespaces/{ns}/app_security/events` | Security events (WAF, bot, DDoS) |
| `POST /api/data/namespaces/{ns}/access_logs` | HTTP access logs |

Authentication is via the `Authorization: APIToken <token>` header.

## Troubleshooting the Tool Itself

| Problem | Solution |
|---------|----------|
| `Config file not found` | Copy `config.yaml.example` to `config.yaml` |
| `401 Unauthorized` | API token is invalid or expired — regenerate it |
| `403 Forbidden` | Token lacks permissions for the namespace — check RBAC |
| `No events found` | Widen `--hours`, verify namespace/LB name, check request ID / IP / FQDN |
| `No search criteria` | Provide at least `--req-id`, `--src-ip`, or `--fqdn` (or set in config) |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |
