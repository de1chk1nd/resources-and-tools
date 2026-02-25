# F5 XC Namespace LB Mover — Reference Guide

Detailed technical documentation for the xc-ns-mover toolset. For a quick-start guide, see the [README](../README.md).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
  - [Tenant & Auth](#tenant--auth)
  - [Namespace Filtering](#namespace-filtering)
  - [Report Settings](#report-settings)
  - [Mover Settings](#mover-settings)
- [Scanner Details](#scanner-details)
- [Mover Details](#mover-details)
  - [How the Mover Works](#how-the-mover-works)
  - [Dependent Objects](#dependent-objects)
  - [Conflict Resolution](#conflict-resolution)
  - [CLI Options](#cli-options)
- [HTML Report Format](#html-report-format)
  - [Report Sections](#report-sections)
  - [Status Codes](#status-codes)
  - [Dependency Graph](#dependency-graph)
- [CSV Formats](#csv-formats)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

---

## Project Structure

```
xc-ns-mover/
├── bin/
│   ├── run-scanner.sh               # Run the scanner
│   └── run-mover.sh                 # Run the mover
├── config/
│   ├── config.yaml                  # Main config (git-ignored)
│   ├── config.yaml.example          # Example — copy and edit
│   ├── xc-mover.csv                 # LBs to move (git-ignored)
│   └── xc-mover.csv.example         # Example — copy and edit
├── docs/
│   └── REFERENCE.md                 # This file
├── reports/                         # Each run creates a timestamped subdirectory
│   ├── scanner_YYYY-MM-DD-HHMM/    # Scanner CSV + HTML report
│   ├── pre-migration_YYYY-MM-DD-HHMM/  # Pre-migration report (--dry-run)
│   └── mover_YYYY-MM-DD-HHMM/         # Mover HTML report (real run)
├── logs/                            # Per-run log files (auto-created)
├── src/
│   └── xc_ns_mover/                # Main package
│       ├── __init__.py
│       ├── __main__.py              # Dispatcher (scanner | mover)
│       ├── config.py                # Shared config loader & validation
│       ├── client.py                # Shared F5 XC API client
│       ├── models.py                # Shared data models (MoveResult, DepMoveResult, etc.)
│       ├── spec_utils.py            # JSON spec walking: find/rewrite namespace refs
│       ├── logging_setup.py         # Dual logging setup (file + console)
│       ├── scanner/                 # Subcommand: list LBs -> CSV + HTML report
│       │   ├── __init__.py
│       │   ├── __main__.py
│       │   └── cli.py
│       ├── mover/                   # Subcommand: move LBs between namespaces
│       │   ├── __init__.py
│       │   ├── __main__.py
│       │   ├── cli.py               # CLI entry point & main migration pipeline
│       │   ├── orchestrator.py      # Discovery, batching (UnionFind), pre-flight phases
│       │   ├── rollback.py          # Atomic rollback on failure
│       │   ├── conflict.py          # Name conflict resolution (skip / rename)
│       │   └── fingerprint.py       # Dry-run fingerprint management
│       └── report/                  # HTML report generation
│           ├── __init__.py
│           ├── base.py              # Shared CSS, JS, HTML page scaffold
│           ├── scanner_report.py    # Scanner HTML report builder
│           ├── mover_report.py      # Mover HTML report builder
│           └── svg_graph.py         # SVG dependency graph renderer
├── requirements.txt
└── README.md
```

### Shared Modules

| Module | Purpose |
|--------|---------|
| `config.py` | Load and validate YAML config, namespace filtering, XC name validation — used by both scanner and mover |
| `client.py` | F5 XC API client (namespace listing, LB CRUD, dependency discovery, certificate portability checks, DNS zone inspection) — used by both |
| `models.py` | Shared dataclasses (`MoveResult`, `DepMoveResult`, `ManualReworkItem`, `BatchGraphData`) and constants (`FRIENDLY_TYPE_NAMES`) |
| `spec_utils.py` | Pure functions for deep-walking XC API JSON specs — find `{name, namespace}` refs, rewrite namespaces, rename objects, rewrite cert refs |
| `logging_setup.py` | Dual logging configuration: file handler (always DEBUG) + console handler (WARNING by default, DEBUG with `--verbose`) |

---

## Installation

For a quick platform-specific setup guide, see the [README](../README.md#1-install-dependencies).

### Prerequisites

- Python 3.9+
- An F5 Distributed Cloud tenant with API access
- An API Token (not a certificate — this tool uses token-based auth)
- Linux or macOS (bash required for the shell wrappers)

### Install Steps

All commands assume you are in the project directory:

```bash
cd tools/xc-ns-mover
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
PYTHONPATH=src python3 -m xc_ns_mover --help
```

If you see `ModuleNotFoundError: No module named 'requests'` or similar, the dependencies are not installed. Re-run `pip install -r requirements.txt`.

---

## Configuration Reference

Copy the example files first:

```bash
cp config/config.yaml.example config/config.yaml
cp config/xc-mover.csv.example config/xc-mover.csv
```

> **Security note:** `config/config.yaml` and `config/xc-mover.csv` are git-ignored. Never commit your API token.

### Tenant & Auth

```yaml
tenant:
  name: "acmecorp"                    # the part before .console.ves.volterra.io

auth:
  api_token: "your-actual-api-token"  # from F5 XC Console
```

### Namespace Filtering

Controls which namespaces the **scanner** scans. The mover ignores these settings — it reads namespaces from the CSV.

```yaml
namespaces:
  include: []    # list of namespaces to scan (empty = all)
  exclude: []    # list of namespaces to skip
```

| Configuration | Behavior |
|---------------|----------|
| Both empty | Scan **all** namespaces the token can access |
| `include` only | Scan **only** the listed namespaces |
| `exclude` only | Scan **all** namespaces **except** the listed ones |
| `include` + `exclude` | Start from the include list, then remove the exclude entries |

**Examples:**

Scan two specific namespaces:

```yaml
namespaces:
  include:
    - "production"
    - "staging"
  exclude: []
```

Scan everything except system namespaces:

```yaml
namespaces:
  include: []
  exclude:
    - "system"
    - "shared"
    - "ves-io"
```

Scan a broad set but carve out exceptions:

```yaml
namespaces:
  include:
    - "dev-frontend"
    - "dev-backend"
    - "dev-legacy"
    - "dev-platform"
  exclude:
    - "dev-legacy"
```

If a namespace appears in both lists, `exclude` wins (a warning is logged).

### Report Settings

```yaml
report:
  output_dir: "reports"    # relative to project root, or absolute path
```

### Mover Settings

```yaml
mover:
  target_namespace: "new-namespace"    # destination for all LBs in the CSV
  conflict_prefix: "migrated"          # prefix for name-conflict renames
```

| Key | Required | Description |
|-----|----------|-------------|
| `target_namespace` | Yes | Destination namespace. All LBs from the CSV are re-created here. |
| `conflict_prefix` | No | Prefix prepended when renaming objects that already exist in the target. Format: `<prefix>-<original-name>`. Required when using `--conflict-action=prefix`. |

---

## Scanner Details

The scanner connects to the F5 XC API, lists all HTTP/HTTPS load balancers across the filtered namespaces, and writes a timestamped CSV + HTML report.

### CLI Options

```
Options:
  --config, -c       Path to YAML config file (default: config/config.yaml)
  --output-dir, -o   Output directory for the CSV report (overrides config)
  --verbose, -v      Enable verbose (debug) logging
```

### Output

The scanner creates a timestamped subdirectory in `reports/` and writes two files:

**CSV** — `reports/scanner_YYYY-MM-DD-HHMM/scanner_YYYY-MM-DD-HHMM.csv`

The CSV includes a comment header with metadata followed by the data:

```csv
# Scanner report — tenant: acmecorp
# Generated: 2026-02-23 10:57
# Namespaces scanned: 2  |  Load balancers found: 4
#
# To use with the mover:
#   1. Copy the rows you need into config/xc-mover.csv
#   2. Only the namespace and lb_name columns are required
#
# --- DATA STARTS BELOW THIS LINE ---
namespace,lb_name,lb_type
production,app-frontend,http_loadbalancer
production,api-gateway,http_loadbalancer
staging,test-app,http_loadbalancer
```

**HTML** — `reports/scanner_YYYY-MM-DD-HHMM/scanner_YYYY-MM-DD-HHMM.html`

A visual report containing:

- **Summary cards** — total LB count, namespaces scanned, namespaces with/without LBs, count per LB type
- **Bar chart** — horizontal bars showing how many LBs each namespace contains, sorted by count
- **LB table** — all discovered load balancers grouped by namespace with type badges (HTTP / HTTPS)
- **CSV for Mover** — a copy-paste-ready CSV block (with copy button) containing all discovered LBs in the format expected by `config/xc-mover.csv`

---

## Mover Details

### How the Mover Works

The mover operates in multiple phases. All discovery and safety checks happen before any mutations.

**Phase 0 — Discovery & batching** (runs once for all LBs):

1. GET the full config of every LB in the CSV
2. Discover dependencies for each LB (origin pools, health checks, certs, ...)
3. **Cluster** LBs that share any dependency into **batches** — LBs with no shared deps get their own single-LB batch

**Phase 0b — Cross-reference scan** (runs once, before any mutations):

1. List **all** LBs in each source namespace (not just the ones in the CSV)
2. For each LB **not** in the move list, fetch its config and scan for references to any of the discovered dependencies
3. Flag any dep that is used by an external LB — these are marked as **external** and shown with a red border in the dependency graph

> **Why an active scan?** The `referring_objects` field returned by the XC API GET response is unreliable — it can be empty even when active references exist. The Phase 0b scan actively checks all LBs in the namespace to detect external references that the API doesn't report. This prevents 409 Conflict errors during deletion.

**Phase 0c — Conflict detection** (runs once, before any mutations):

1. List all existing objects in the **target** namespace (LBs + each dependency type)
2. Compare with the objects about to be moved — flag any name that already exists
3. For each conflict, either **skip** the object or **rename** it with the configured `conflict_prefix`
4. In interactive mode (`--conflict-action=ask`, the default), the user is prompted per object
5. In batch mode, `--conflict-action=skip` or `--conflict-action=prefix` resolves automatically

**Phase 0d — Certificate private key pre-flight** (runs once, before any mutations):

1. Check every TLS certificate dependency for non-portable private keys (blindfolded, clear secret, vault reference, wingman)
2. For each non-portable certificate, extract the domains (CN + SANs) from the `infos` field
3. List all certificates in the **target** namespace and the **shared** namespace
4. **Match** each non-portable cert against the available certs by comparing the LB's `domains` against the cert's CN/SANs (including wildcard matching per RFC 6125)
5. **Match found** — the LB's cert reference is automatically rewritten to point to the matched cert (name + namespace). The original cert stays in the source namespace untouched.
6. **No match** — the entire batch containing the affected LB(s) is **blocked**. The report shows which cert is missing and what domains it needs to cover. Create the cert in the target or shared namespace and re-run the mover.

> **Why can't certificates with private keys be moved?** The XC API never returns private key material in cleartext. Whether the key is blindfolded, stored as a clear secret, referenced from a vault, or managed by wingman — the GET response only contains an opaque reference. Re-creating the certificate in a new namespace requires the original private key, which must be uploaded manually. Cross-namespace certificate references are also not supported (only the `shared` namespace is accessible from other namespaces).

**Phase 0e — DNS zone pre-flight** (runs once, before any mutations):

1. Queries `GET /api/config/dns/namespaces/system/dns_zones` to discover primary DNS zones hosted by the tenant
2. For each zone, fetches the full config and checks for the "Allow Application Loadbalancer Managed Records" setting
3. For each Let's Encrypt LB, checks if **all** domains fall under a managed zone
4. Managed LBs are marked as `AUTO-MANAGED` in the DNS table — no manual DNS action is required
5. If the API returns 403/404 (insufficient permissions), a warning is shown and all LBs are treated as requiring manual DNS updates

> **What is managed DNS?** F5 XC can host primary DNS zones. When a zone has "Allow Application Loadbalancer Managed Records" enabled, XC automatically creates/updates A/CNAME records and `_acme-challenge` CNAME records when an HTTP LB is created or moved. In that case, the customer does **not** need to manually update DNS after migration — they just need to verify the records were created in the F5 XC Console.

**Per batch** (atomic — all-or-nothing):

1. **Backup** all LB + dependency configs (stored for rollback + report)
2. **Safety check:** For each dependency, check if any *external* objects (not in the move list) reference it — using both the API `referring_objects` field and the Phase 0b active scan results. If so, the batch is **blocked**.
3. **Delete (top-down):** Delete ALL LBs in the batch first, then run a pre-flight probe on each dep (DELETE with `fail_if_referred=true`) to catch any remaining external refs the scan may have missed. If clear, delete all dependencies (parents before leaves).
4. **Create (bottom-up):** Create leaf dependencies first (health checks, etc.), then origin pools, then ALL LBs. Renamed objects use the new names; all internal JSON references are updated automatically.
5. **Verify** — GET each new LB config to capture the new CNAME
6. **On failure — Rollback:** If any step fails, undo all changes: delete anything created in the target, re-create everything deleted from the source

> **Why batch LBs together?** F5 XC enforces referential integrity. If LB-A and LB-B both reference the same origin pool, you cannot delete that pool while either LB still exists. By batching them, we delete both LBs first (freeing all references), then delete the shared pool, then re-create everything in the target namespace.

> **Why top-down delete / bottom-up create?** You cannot delete a dependency still referenced by an LB. Deleting LBs first removes the references. Conversely, you must create dependencies before the LB that references them.

> **CNAME / ACME Warning:** When an LB is moved (or reverted), F5 XC may assign a new `host_name` (CNAME). If you use Let's Encrypt auto-cert, the ACME challenge domain will also change. Update your DNS records accordingly.

#### Three-layer external reference detection

The mover uses three independent methods to detect external referrers:

1. **Phase 0b active scan** — fetches configs of all LBs in the namespace and checks for references to the deps being moved (most reliable)
2. **Phase 2 `referring_objects`** — reads the API's referrer list from the dep GET response (unreliable — may be empty)
3. **Phase 3b pre-flight probe** — after deleting the batch's LBs, attempts a DELETE with `fail_if_referred=true` on each dep; a 409 response reveals hidden external referrers

If any layer detects an external referrer, the batch is **blocked** with a clear error listing who references the object. To proceed, either add the referencing LBs to the move list or handle the shared dependency manually.

### Dependent Objects

The mover detects and moves the following object types when they live in the same namespace as the LB:

| Object Type | API Resource |
|-------------|-------------|
| Origin Pools | `origin_pools` |
| Health Checks | `healthchecks` |
| TLS Certificates | `certificates` |
| Service Policies | `service_policys` |
| API Definitions | `api_definitions` |
| App Firewalls | `app_firewalls` |
| IP Prefix Sets | `ip_prefix_sets` |
| Rate Limiters | `rate_limiter_policys` |
| User Identifications | `user_identifications` |

**Rules:**

- Objects in the `system` and `shared` namespaces are **never** moved
- Objects referenced from other namespaces are left in place — only same-namespace dependencies are moved
- **TLS Certificates** with private key secrets (blindfolded, clear, vault, wingman) **cannot** be moved automatically. The Phase 0d pre-flight check searches for a matching cert in the target or shared namespace. See [Certificate Pre-Flight](#phase-0d--certificate-private-key-pre-flight) for details.
- Dependencies shared between multiple LBs are moved once and de-duplicated
- LBs that are already in the target namespace are automatically skipped

### Conflict Resolution

When an object with the same name already exists in the target namespace, the mover detects the conflict in Phase 0c (before any mutations) and offers two options:

1. **Skip** — do not move this object; leave the existing one in the target namespace untouched. If a dependency is skipped, the LB will reference the pre-existing object in the target.
2. **Rename** — prepend the `conflict_prefix` from config and create the object under the new name. All internal JSON references are updated automatically.

**Interactive mode** (`--conflict-action=ask`, the default):

```
CONFLICT: HTTP LB 'my-app-lb' already exists in target namespace.
  [s] Skip this object
  [r] Rename to 'migrated-my-app-lb'
  Choose [s/r]:
```

**Batch / CI mode** — no prompts:

| Flag | Behavior |
|------|----------|
| `--conflict-action=skip` | Skip all conflicting objects automatically |
| `--conflict-action=prefix` | Rename all conflicting objects using the configured prefix |

> **Tip:** For fully non-interactive operation (CI/CD pipelines, batch jobs), combine `--force-all` with `--conflict-action=skip` or `--conflict-action=prefix`.

**How reference rewriting works:**

When a dependency is renamed (e.g. origin pool `my-pool` → `migrated-my-pool`), the mover deep-walks every `{name, namespace}` reference dict in:
- The LB spec
- Other dependency specs (e.g. an origin pool referencing a health check)

Any reference matching the old name + target namespace is rewritten to use the new name. This ensures the created objects form a consistent graph.

### CLI Options

```
Options:
  --config, -c         Path to YAML config file (default: config/config.yaml)
  --force-all          Skip per-LB confirmation prompts — move all without asking
  --dry-run            Simulate the move — no changes, generates report with planned JSON configs
  --skip-dry-run       Skip the dry-run verification check (see below)
  --conflict-action    Action when a name conflict exists in the target namespace:
                         ask    — prompt interactively per object (default)
                         skip   — automatically skip conflicting objects
                         prefix — automatically rename with the configured conflict_prefix
  --verbose, -v        Enable verbose (debug) logging
```

### Dry-Run Verification

The mover enforces that a dry-run has been performed before executing a real move. This helps prevent accidental changes by ensuring the operator has reviewed the planned migration report.

**How it works:**

1. When you run with `--dry-run`, the mover generates a **fingerprint** (SHA-256 hash of the tenant name, target namespace, and CSV content) and stores it in `config/.mover_dryrun_fingerprint`.
2. When you run without `--dry-run` (a real move), the mover checks for this fingerprint:
   - **Match** — the dry-run was done with the same config. The move proceeds normally.
   - **Mismatch** — the config changed since the last dry-run (e.g. CSV was edited, target namespace changed). The user must type `SKIP-DRYRUN` to continue or re-run the dry-run.
   - **Missing** — no dry-run was ever performed. The user must type `SKIP-DRYRUN` to continue.
3. After a successful real run, the fingerprint is deleted (one-time use). A new dry-run is required before the next real run.

**Bypassing the check:**

- **Interactively:** Type `SKIP-DRYRUN` when prompted
- **CLI flag:** Use `--skip-dry-run` (for CI/CD pipelines or experienced operators)

> **Tip:** For fully automated pipelines, run `--dry-run` first, then `--skip-dry-run --force-all --conflict-action=skip` for the real run. The fingerprint ensures the config hasn't changed between steps.

---

## HTML Report Format

After completing (or partially completing) a move run, the mover generates an HTML report:

```
reports/pre-migration_YYYY-MM-DD-HHMM/pre-migration_YYYY-MM-DD-HHMM.html   # --dry-run
reports/mover_YYYY-MM-DD-HHMM/mover_YYYY-MM-DD-HHMM.html                  # real run
```

### Report Sections

**Health Indicator** — colored banner at the very top of the report showing the overall migration health at a glance:

| Color | Meaning |
|-------|---------|
| **Green** | All migrations completed successfully (or planned in dry-run) |
| **Yellow** | Some migrations were skipped, blocked, or reverted — review details |
| **Orange** | Manual rework required — certificate(s) with non-portable private keys |
| **Red** | Critical failure — one or more migrations failed |

The banner includes a count summary (e.g. "3 moved | 1 failed | 1 blocked") and, for non-green status, lists up to 3 affected load balancers and up to 3 error messages for quick triage.

**Load Balancers** — summary cards + table:

| Column | Description |
|--------|-------------|
| HTTP LB Name | Load balancer name. Shows a rename badge (→ new-name) if renamed due to conflict. Links to planned config in dry-run mode. |
| Namespace (old) | Source namespace before the move |
| Namespace (new) | Target namespace after the move |
| TLS | TLS mode: **No TLS**, **Manual TLS**, or **Let's Encrypt** |
| CNAME (old) | The `host_name` (CNAME target) before the move |
| CNAME (new) | The new `host_name` assigned after the move (highlighted if changed) |
| Status | See [Status codes](#status-codes) below |
| Error | Error details (if failed or blocked) |

**CNAME / ACME Warning** — shown at the top when any LB was moved or reverted. Warns that DNS records may need updating and Let's Encrypt certificates will be re-issued.

**Manual Rework Needed** — shown when certificates with non-portable private keys are detected. Contains:

- **Matched Certificates** — certs that were matched to an existing cert in the target or shared namespace. The LB reference was automatically rewritten. Shows the original cert name, matched cert name/namespace, and the matched cert's domains.
- **Unmatched Certificates** — certs for which no match was found. The affected batches are blocked. Shows the required domains, secret type, and instructions for manually creating the cert.
- **Original Certificate Configurations** — collapsible JSON backups of the non-portable certs for reference.

**Dependencies** — collapsible section containing:

- **Dependent Objects** — table listing every dependency processed (parent LB, object type/name, status, error). Renamed dependencies show a badge.
- **Dependency Graph** — SVG visualization of the dependency tree per batch (see below).

**Planned Configurations** — (dry-run only) collapsible JSON blocks showing the exact API request body for each LB.

**Original Configuration Backups** — collapsible section with full GET responses captured before any changes. Grouped by LB with nested dependencies. Shared deps appear once with cross-references.

### Status Codes

| Status | Applies to | Meaning |
|--------|-----------|---------|
| **MOVED** | LB, Dep | Successfully deleted from source and created in target namespace |
| **DRY-RUN** | LB, Dep | Would be moved (dry-run mode — no changes made) |
| **BLOCKED** | LB, Dep | Cannot be moved — a dependency is referenced by an external object. The error shows which object holds the reference. **Fix:** add the referencing LB to the CSV, or remove the external reference. |
| **FAILED** | LB, Dep | An API call failed (DELETE or CREATE returned an error). If rollback succeeded, status is REVERTED. |
| **REVERTED** | LB, Dep | Move failed and the object was restored to source. **Check the CNAME** — it may have changed. |
| **SKIPPED** | LB | User chose "no" at prompt, LB is already in target, or name conflict was skipped |
| **MANUAL-REWORK** | Dep | TLS certificate with non-portable private key. If a matching cert was found in target/shared, the LB reference was auto-rewritten. Otherwise the batch is blocked until the cert is created manually. |

### Dependency Graph

Each batch gets an SVG dependency graph. Rendering mode depends on complexity:

**Simple chain** (single LB, no shared deps) — compact vertical flow:

```
  HTTP LB
    ↓
  Origin Pool
    ↓
  Health Check
```

**Full graph** (multiple LBs or shared deps) — multi-column layout:

```
  LB-A          LB-B
    \           / |
     Origin Pool  Origin Pool-B
        |             |
     Health Check  Health Check-B
```

**Node border colors:**

| Border | Meaning |
|--------|---------|
| **Red thick** | Used by an external object not in the move list — cannot be moved |
| **Orange thick** | Shared within the batch — used by multiple LBs (moved atomically) |
| Teal thin | Normal direct dependency |
| Grey thin | Leaf sub-dependency |

**Batch tags:**

- `Batch N` — standard single-LB batch
- `Batch N (atomic)` — multi-LB batch (LBs share deps, moved together)
- `Batch N (shared deps)` — single-LB batch with shared dependencies

---

## CSV Formats

### Scanner output (`reports/scanner_YYYY-MM-DD-HHMM/scanner_YYYY-MM-DD-HHMM.csv`)

```csv
namespace,lb_name,lb_type
production,app-frontend,http_loadbalancer
staging,test-app,http_loadbalancer
```

### Mover input (`config/xc-mover.csv`)

```csv
namespace,lb_name
production,app-frontend
staging,test-app
```

Lines starting with `#` are treated as comments and ignored. The `lb_type` column is optional (the mover ignores it if present).

---

## API Endpoints

| Endpoint | Used by | Purpose |
|----------|---------|---------|
| `GET /api/web/namespaces` | scanner | List all accessible namespaces |
| `GET /api/config/namespaces/{ns}/http_loadbalancers` | scanner, mover | List HTTP LBs in a namespace |
| `GET /api/config/namespaces/{ns}/https_loadbalancers` | mover | List HTTPS LBs (Phase 0b cross-ref scan) |
| `GET /api/config/namespaces/{ns}/http_loadbalancers/{name}` | mover | Get full LB config |
| `DELETE /api/config/namespaces/{ns}/http_loadbalancers/{name}` | mover | Delete LB from source namespace |
| `POST /api/config/namespaces/{ns}/http_loadbalancers` | mover | Create LB in target namespace |
| `GET /api/config/namespaces/{ns}/certificates` | mover | List certificates in namespace (Phase 0d pre-flight) |
| `GET /api/config/namespaces/{ns}/certificates/{name}` | mover | Get full certificate config incl. infos (Phase 0d) |
| `GET /api/config/dns/namespaces/system/dns_zones` | mover | List DNS zones (Phase 0e managed DNS detection) |
| `GET /api/config/dns/namespaces/system/dns_zones/{name}` | mover | Get full DNS zone config (Phase 0e) |
| `GET /api/config/namespaces/{ns}/{type}/{name}` | mover | Get dependent object config |
| `DELETE /api/config/namespaces/{ns}/{type}/{name}` | mover | Delete dependent object (`fail_if_referred=false` for actual delete, `true` for pre-flight probe) |
| `POST /api/config/namespaces/{ns}/{type}` | mover | Create dependent object in target namespace |

Authentication: `Authorization: APIToken <token>` header on every request.

---

## Troubleshooting

### Common Errors

| Problem | Solution |
|---------|----------|
| `Config file not found` | Copy `config.yaml.example` to `config.yaml` and fill in your values |
| `Input CSV not found` | Copy `xc-mover.csv.example` to `xc-mover.csv` and add your LBs |
| `401 Unauthorized` | API token is invalid or expired — regenerate it in F5 XC Console |
| `403 Forbidden` | Token lacks permissions for the namespace — skipped automatically |
| `No namespaces to scan` | Check your include/exclude filter — it may be too restrictive |
| `mover.target_namespace is not set` | Set the destination namespace in `config/config.yaml` |

### Move Failures

| Problem | Solution |
|---------|----------|
| `BLOCKED` — dep used by external LB | A dependency is referenced by an LB not in the CSV. The error and dependency graph (red border) show which LB. **Fix:** add it to `xc-mover.csv`, or reassign the reference. |
| `BLOCKED` — 409 Conflict on dep delete | The API refused to delete because something still references it. Caught by Phase 3b pre-flight probe. Batch is rolled back. Check the error for referrer details. |
| `FAILED to create` after delete | Create failed in target — automatic rollback is attempted. Check the HTML report for details. |
| `REVERTED` status in report | Move failed and the object was restored to source. **Verify the CNAME** — it may differ from the original. |
| CNAME changed after move | F5 XC assigns a new `host_name`. Update your DNS records. Let's Encrypt certs are re-issued after DNS propagation. |
| `MANUAL-REWORK` — cert with private key | The certificate has a non-portable private key. If a match was found in target/shared, the reference was auto-rewritten. Otherwise: create the cert in the target or shared namespace (covering the required domains), then re-run the mover. |
| `BLOCKED` — unmatched certificate | No cert in target/shared covers the LB's domains. Create the missing cert and re-run. The report's "Manual Rework Needed" section lists the required domains. |

### Conflict Issues

| Problem | Solution |
|---------|----------|
| Name conflict in target namespace | Use `--conflict-action=skip` to skip, or `--conflict-action=prefix` to rename with the configured prefix |
| `--conflict-action=prefix` but no prefix set | Set `mover.conflict_prefix` in `config/config.yaml` (e.g. `conflict_prefix: "migrated"`) |

### Dry-Run Verification

| Problem | Solution |
|---------|----------|
| "No dry-run has been performed" | Run with `--dry-run` first to generate a report and fingerprint, then re-run without `--dry-run` |
| "Configuration has changed since last dry-run" | The CSV, target namespace, or tenant was modified after the dry-run. Re-run `--dry-run` to verify the new config, or type `SKIP-DRYRUN` to continue |
| Want to skip the check in CI/CD | Use `--skip-dry-run` flag |

### Performance

| Problem | Solution |
|---------|----------|
| Phase 0b scan is slow | The cross-reference scan fetches configs for all non-move-set LBs in the namespace. For namespaces with many LBs this adds startup time, but prevents 409 failures during the actual move. |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |

### Python Environment

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'requests'` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'yaml'` | Run `pip install -r requirements.txt` (installs PyYAML) |
| `SyntaxError` on startup | Python 3.9+ is required. Check with `python3 --version`. |
| Permission denied on `run-scanner.sh` | Run `chmod +x bin/run-scanner.sh bin/run-mover.sh` |
| Virtual environment not activated | Run `source venv/bin/activate` before running the tool |
