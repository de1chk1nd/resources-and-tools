# F5 XC Namespace LB Mover

Move HTTP load balancers (and their dependencies) between F5 Distributed Cloud namespaces.

| Command | Script | What it does |
|---------|--------|-------------|
| **Scanner** | `./bin/run-scanner.sh` | List all LBs across namespaces → CSV report |
| **Mover** | `./bin/run-mover.sh` | Move LBs from the CSV into a target namespace |

---

**Scanner**: Scanner allows to list all HTTP load balancers in all namespaces and creates a CSV output. This output can be used to feed the **Mover** script.

**Mover**: Mover has two main components:

- a migration report, listing details about the planned job, incl. common issues, list of migration dependencies, and a copy-paste-ready JSON file to migrate apps
- an **execution** logic, to automatically apply changes

> Applying the changes will cause a brief interruption and should be executed in a controlled environment / change window.

---

## Things to consider

- Script logic (XC logic) is to delete/re-create HTTP LB — a simple "reconfiguration" of the "namespace" attribute is not possible (neither via UI nor via API)
  - Re-creating will cause generating a new CNAME for the A record
  - Re-creating will cause generating a new CNAME for the DNS Let's Encrypt challenge

- Imported certificates can't be migrated — they need to be re-created in the new namespace
  - Certificates with non-portable private keys (blindfolded, clear secret, vault reference, wingman) cannot be extracted via the API. The mover's pre-flight check (Phase 0d) searches for a matching certificate in the target or shared namespace by domain/SAN. If no match is found, the affected batch is **blocked** until the certificate is manually created.

- Sometimes objects share another object (e.g. same origin pool in two different HTTP load balancers; health check shared across different origin pools)
  - If a shared object is within the `system` or `shared` namespace, nothing needs to be done
  - If an object is stored in the "source" namespace, it must be:
    1. re-created in the new namespace
    2. cross-namespace references (except `system` and `shared`) are not allowed — all objects must be moved or the dependency must be resolved before migration
    3. the migration report will take care of identifying the dependencies and listing common issues

- A dry-run (`--dry-run`) is enforced before a real move — the mover stores a fingerprint after a dry-run and verifies it before executing. If the configuration changes (CSV, target namespace, or tenant), a new dry-run is required. This can be bypassed with `--skip-dry-run`.

- If a move fails mid-way, the mover automatically attempts a **rollback** (restore deleted objects to the source namespace). After rollback, the CNAME may differ from the original — always verify DNS records.

- The tool currently only supports **HTTP load balancers**. TCP load balancers and other object types are not migrated.

- API token expiration: the F5 XC API token has a limited lifetime. If the token expires during a long migration run, subsequent API calls will fail. Ensure the token has sufficient validity before starting.

---

<h2 align="center">Setup</h2>
<p align="center"><em>Install dependencies, create an API token, configure — then you're ready to go.</em></p>

---

## Quick Start

### 1. Install dependencies

All commands assume you are in the project directory:

```bash
cd tools/xc-ns-mover
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

Make the wrapper scripts executable (only needed once after cloning):

```bash
chmod +x bin/run-scanner.sh bin/run-mover.sh
```

<br>

Verify everything is working:

```bash
python3 --version          # must be 3.9+
pip show requests PyYAML   # both should be listed
```

<br>

### 2. Get an API Token

1. Log into your F5 XC Console
2. Go to **Administration → Credentials → API Credentials**
3. Click **Create Credentials** → select **API Token** → **Generate**
4. Copy the token

<br>

### 3. Configure

Copy the example files:

```bash
cp config/config.yaml.example config/config.yaml
```

<br>

Edit `config/config.yaml` — fill in your tenant name and token:

```yaml
tenant:
  name: "acmecorp"                  # <tenant>.console.ves.volterra.io

auth:
  api_token: "your-api-token"

mover:
  target_namespace: "new-namespace"
  conflict_prefix: "migrated"       # used when a name already exists in the target
```

---

<h2 align="center">Usage</h2>
<p align="center"><em>Scan your tenant, pick what to move, verify, migrate.</em></p>

---

## Scanner

Lists all HTTP load balancers across namespaces and writes a CSV + HTML report to `reports/`.

> See [reports/examples/scanner_example.html](reports/examples/scanner_example.html) for an example report.

```bash
./bin/run-scanner.sh                              # scan all namespaces
./bin/run-scanner.sh --verbose                    # with debug output
./bin/run-scanner.sh --config /path/to/config.yaml  # custom config
```

<br>

<details>
<summary><strong>Options</strong></summary>

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to YAML config file (default: `config/config.yaml`) |
| `--output-dir, -o` | Output directory for reports (overrides config) |
| `--verbose, -v` | Debug logging |

You can filter namespaces in `config.yaml` — see the [reference guide](docs/REFERENCE.md#namespace-filtering) for details.

</details>

---

## Mover

Moves HTTP load balancers (and their dependencies) from the CSV into a target namespace. Generates an HTML report in `reports/`.

> Example reports: [pre-migration (--dry-run)](reports/examples/pre-migration_example.html) | [migration (real run)](reports/examples/mover_example.html)

### 1. Prepare the input CSV

Copy the rows you want from the scanner output into `config/xc-mover.csv`:

```bash
cp config/xc-mover.csv.example config/xc-mover.csv
```

Only `namespace` and `lb_name` are required:

```csv
namespace,lb_name
production,app-frontend
production,api-gateway
```

<br>

### 2. Pre-migration verification

Always run a dry-run first — it generates a **Pre-Migration Report** with planned configs, dependency analysis, certificate checks, and conflict detection. No changes are made.

```bash
./bin/run-mover.sh --dry-run
```

<br>

### 3. Execute the migration

After reviewing the report:

```bash
./bin/run-mover.sh                    # interactive — confirm each batch
./bin/run-mover.sh --force-all        # skip all prompts
```

<br>

<details>
<summary><strong>Options</strong></summary>

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to YAML config file (default: `config/config.yaml`) |
| `--force-all` | Skip all confirmation prompts |
| `--dry-run` | Pre-migration report only — no changes |
| `--conflict-action` | Name conflict handling: `ask` (default), `skip`, or `prefix` |
| `--verbose, -v` | Debug logging |

</details>

<br>

<details>
<summary><strong>Name conflicts</strong></summary>

When an object with the same name already exists in the target namespace, the mover prompts:

```
CONFLICT: HTTP LB 'my-app-lb' already exists in target namespace.
  [s] Skip this object
  [r] Rename to 'migrated-my-app-lb'
  Choose [s/r]:
```

The prefix comes from `mover.conflict_prefix` in your config. For batch/CI use:

```bash
./bin/run-mover.sh --force-all --conflict-action=skip     # skip conflicts
./bin/run-mover.sh --force-all --conflict-action=prefix   # auto-rename
```

</details>

---

<h2 align="center">Reference</h2>
<p align="center"><em>Status codes, troubleshooting, and further documentation.</em></p>

---

## Status Codes

Both LBs and dependencies use these status codes in the HTML report:

| Status | Meaning |
|--------|---------|
| **MOVED** | Deleted from source, created in target |
| **DRY-RUN** | Would be moved (pre-migration verification, no changes made) |
| **BLOCKED** | A dependency is referenced by an external object not in the move list |
| **FAILED** | An API call failed (see error column) |
| **REVERTED** | Move failed and the object was restored to the source namespace |
| **SKIPPED** | User chose "no", LB is already in the target, or name conflict skipped |

---

## Common Issues

| Problem | Fix |
|---------|-----|
| `Config file not found` | Run `cp config/config.yaml.example config/config.yaml` |
| `Input CSV not found` | Run `cp config/xc-mover.csv.example config/xc-mover.csv` |
| `401 Unauthorized` | API token is invalid or expired — regenerate it |
| `403 Forbidden` | Token lacks permissions — namespace is skipped automatically |
| `mover.target_namespace is not set` | Set it in `config/config.yaml` |
| `BLOCKED` in report | A dependency is used by another LB not in your CSV — add it to the CSV or reassign the external reference |
| CNAME changed after move | F5 XC assigns a new CNAME — see the "DNS Changes" section in the HTML report for old/new values |
| Name conflict in target | Use `--conflict-action=skip` or `--conflict-action=prefix` |

---

For detailed troubleshooting, internal architecture, config reference, API details, and report format documentation see the **[Reference Guide](docs/REFERENCE.md)**.
