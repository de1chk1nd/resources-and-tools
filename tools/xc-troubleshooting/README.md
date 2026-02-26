# F5 XC WAAP Troubleshooting Tool

Query F5 Distributed Cloud (XC) security event logs and access logs by **request ID**, **source IP**, **FQDN**, or any combination — and generate a local troubleshooting report.

| Search mode | Example |
|-------------|---------|
| Request ID | `./bin/run-troubleshoot.sh --req-id "abc12345-..."` |
| Source IP | `./bin/run-troubleshoot.sh --src-ip "203.0.113.42"` |
| FQDN | `./bin/run-troubleshoot.sh --fqdn "api.example.com"` |
| Combined | `./bin/run-troubleshoot.sh --src-ip "203.0.113.42" --fqdn "api.example.com"` |
| + Load Balancer | any of the above + `--load-balancer "my-app-lb"` |

You can start with a request ID, then pivot to the source IP to see all events from that client. Use `--fqdn` and `--load-balancer` as optional filters to narrow results.

---

## Things to consider

- The default namespace is `system`, which queries across **all namespaces**. If you know the specific namespace, use `--namespace` to narrow the search — this can improve result accuracy.

- The default search window is **24 hours**. If the event you're looking for happened earlier, widen it with `--hours 48` (or more).

- The tool queries two independent API endpoints: **security events** and **access logs**. If one fails, the other still runs — the report will show an API error banner indicating which query failed.

- Security events only exist when a security policy (WAF, Bot Defense, API Protection, etc.) triggers. If a request was allowed without violations, only access logs will be present. This is expected behavior — the verdict will be **ALLOWED**.

- Input validation is enforced on all search parameters before they are embedded in API queries. Values containing quotes, braces, backslashes, or newlines are rejected to prevent query injection.

- API token expiration: the F5 XC API token has a limited lifetime. If the token expires during use, API calls will return 401. Ensure the token is still valid before running.

---

<h2 align="center">Setup</h2>
<p align="center"><em>Install dependencies, create an API token, configure — then you're ready to go.</em></p>

---

## Quick Start

### 1. Install dependencies

All commands assume you are in the project directory:

```bash
cd tools/xc-troubleshooting
```

Make sure Python 3.9+ is installed. Install the system packages for your platform if needed:

<details>
<summary><strong>Linux (Debian/Ubuntu)</strong></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

</details>

<details>
<summary><strong>Linux (RHEL/Fedora)</strong></summary>

```bash
sudo dnf install python3 python3-pip
```

</details>

<details>
<summary><strong>macOS</strong></summary>

macOS ships with Python 3 since Catalina (10.15). If `python3 --version` shows
nothing or a version below 3.9, install it via [Homebrew](https://brew.sh):

```bash
brew install python@3
```

> **Note:** You may see a prompt to install Xcode Command Line Tools the first
> time you run `python3` or `git`. Accept it — no full Xcode install is needed.

</details>

<br>

Then set up a virtual environment and install the dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

<br>

Make the shell wrapper executable:

```bash
chmod +x bin/run-troubleshoot.sh
```

<br>

Verify everything is working:

```bash
python3 --version          # must be 3.9+
pip show requests PyYAML   # both should be listed
./bin/run-troubleshoot.sh --help
```

<br>

### 2. Get an API Token

1. Log into your F5 XC Console
2. Go to **Administration → Credentials → API Credentials**
3. Click **Create Credentials** → select **API Token** → **Generate**
4. Copy the token

<br>

### 3. Configure

Copy the example config:

```bash
cp config/config.yaml.example config/config.yaml
```

<br>

Edit `config/config.yaml` — fill in your tenant name and token:

```yaml
tenant:
  name: "acmecorp"                  # <tenant>.console.ves.volterra.io

auth:
  api_token: "your-api-token"       # or use XC_API_TOKEN env var instead
```

> **Security note:** `config/config.yaml` is git-ignored. Never commit your API token. For environments where files are risky, use `XC_API_TOKEN` as an env var instead — it takes precedence over the YAML value.

---

<h2 align="center">Usage</h2>
<p align="center"><em>Search security events, generate a report, investigate.</em></p>

---

## Running the tool

```bash
./bin/run-troubleshoot.sh --req-id "abc123"
```

The shell wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

<details>
<summary><strong>Alternative: run as Python module directly</strong></summary>

If you prefer not to use the shell wrapper:

```bash
source venv/bin/activate
PYTHONPATH=src python3 -m xc_troubleshoot --req-id "abc123"
```

Or via the legacy entry point:

```bash
python3 src/xc_troubleshoot.py --req-id "abc123"
```

</details>

<br>

### Examples

```bash
# Search by request ID
./bin/run-troubleshoot.sh --req-id "abc12345-6789-def0-1234-567890abcdef"

# Search by source IP — last 48h
./bin/run-troubleshoot.sh --src-ip "203.0.113.42" --hours 48

# Search by FQDN
./bin/run-troubleshoot.sh --fqdn "api.example.com"

# Combine filters
./bin/run-troubleshoot.sh --src-ip "203.0.113.42" --fqdn "api.example.com" --load-balancer "my-app-lb"

# Include public research for known issues
./bin/run-troubleshoot.sh --req-id "abc123" --research

# Query a specific namespace (default: system = all namespaces)
./bin/run-troubleshoot.sh --src-ip "10.0.0.1" --namespace "production"

# With debug output
./bin/run-troubleshoot.sh --req-id "abc123" --verbose

# Use env var for token
XC_API_TOKEN="your-token" ./bin/run-troubleshoot.sh --req-id "abc123"
```

<br>

<details>
<summary><strong>Options</strong></summary>

| Flag | Description |
|------|-------------|
| `--req-id, -r` | Request ID to search for (overrides config) |
| `--src-ip, -s` | Source IP to search for (overrides config) |
| `--fqdn, -d` | FQDN / hostname to filter by (overrides config) |
| `--load-balancer, -l` | Load balancer name to filter by (overrides config) |
| `--namespace, -n` | Namespace to query (default: `system` = all namespaces) |
| `--config, -c` | Path to YAML config file (default: `config/config.yaml`) |
| `--format, -f` | Report format (default: `html`) |
| `--hours` | Search window in hours (default: 24) |
| `--limit` | Max events per query (default: 50) |
| `--output-dir, -o` | Output directory for reports (overrides config) |
| `--research` | Search F5 public docs & community for known issues |
| `--verbose, -v` | Debug logging |

</details>

---

## Report Output

Reports are saved as self-contained HTML files to the `reports/` directory (configurable). Filenames follow the pattern:

```
report_<search_label>_<timestamp>.html
```

The report is a single-file HTML document with embedded CSS — no external dependencies. Open it in any browser.

<br>

<details>
<summary><strong>Report contents</strong></summary>

- **Header** — search mode, filters used, tenant, namespace, time window
- **Traffic Flow Diagram** — SVG visualization of the request path (Client → RE → App), with per-segment latency and TLS info. When multiple requests are aggregated (e.g. search by IP), latencies are averaged and each node shows a hover tooltip with all unique IPs, FQDNs, sites, and min/max latency.
- **API Error Banner** *(if any queries failed)* — warns that the report may be incomplete
- **Verdict Banner** — BLOCKED / MONITORED / ALLOWED / NO DATA / INFO
- **Overview** — event counts, response code distribution, security event breakdown, unique IPs/requests
- **Key Findings** — context-aware troubleshooting hints with full WAF context (signatures, threat campaigns, attack types, risk rating, actionable recommendations with specific signature IDs)
- **Services Enabled** — SVG pipeline diagram of all security services on the HTTP LB (WAF, Bot Defense, DDoS, API Protection, Rate Limiting, IP Reputation, MUD, etc.), with collapsible detail tables showing service mode, policy names, and resolved user identification details (identifier type such as cookie name, client IP, TLS fingerprint)
- **Detailed Security Events** — collapsible per-event details (WAF action, policy, rule hits, JWT, OAS, bot classification, geo, TLS fingerprint)
- **Detailed Access Logs** — collapsible per-request details (timing, upstream info, response flags, policy results)
- **Public Research** *(optional, `--research`)* — links to F5 docs, DevCentral, and MyF5 articles
- **Raw JSON data** — collapsible sections with the full API response and copy-to-clipboard button

</details>

---

<h2 align="center">Reference</h2>
<p align="center"><em>Status codes, troubleshooting, and further documentation.</em></p>

---

## Verdict Types

The report banner shows an overall assessment of the search results:

| Verdict | Color | Meaning |
|---------|-------|---------|
| **BLOCKED** | Red | One or more requests blocked by security policy |
| **MONITORED** | Yellow | Security events reported but not blocked (WAF in monitor mode) |
| **ALLOWED** | Green | Access logs exist but no security events — request passed cleanly |
| **NO DATA** | Grey | No events or logs found for the search criteria |
| **INFO** | Blue | Events found — review details for assessment |

---

## Common Issues

| Problem | Fix |
|---------|-----|
| `Config file not found` | Run `cp config/config.yaml.example config/config.yaml` |
| `Missing or placeholder API token` | Set `XC_API_TOKEN` env var or edit `config.yaml` |
| `Invalid characters in ...` | Input validation rejected unsafe characters — check your values |
| `401 Unauthorized` | API token is invalid or expired — regenerate it |
| `403 Forbidden` | Token lacks permissions for the namespace — check RBAC |
| `No events found` | Widen `--hours`, try `--namespace` to query a specific namespace, verify search criteria |
| `No search criteria` | Provide at least `--req-id`, `--src-ip`, or `--fqdn` (or set in config) |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |
| `Report shows "API queries failed"` | One or both API calls failed — check the error in the report |
| `Permission denied on run-troubleshoot.sh` | Run `chmod +x bin/run-troubleshoot.sh` |

---

For project structure, module architecture, config reference, security details, API endpoints, report format documentation, and extending the tool — see the **[Reference Guide](docs/REFERENCE.md)**.
