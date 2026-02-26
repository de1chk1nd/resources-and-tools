# S-Certificate — Reference Guide

Detailed technical documentation for the s-certificate tool. For a quick-start guide, see the [README](../README.md).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
  - [Certificate Settings](#certificate-settings)
  - [CA Settings](#ca-settings)
  - [Distinguished Name](#distinguished-name)
  - [XC Settings](#xc-settings)
- [CLI Options](#cli-options)
- [How the Tool Works](#how-the-tool-works)
  - [Certificate Generation Pipeline](#certificate-generation-pipeline)
  - [XC Upload Details](#xc-upload-details)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

---

## Project Structure

```
s-certificate/
├── bin/
│   └── run-s-certificate.sh         # Run the certificate generator
├── config/
│   ├── config.yaml                  # Main config (git-ignored)
│   ├── config.yaml.example          # Example — copy and edit
│   ├── domains.txt                  # Domain list for batch mode (git-ignored)
│   └── domains.txt.example          # Example — copy and edit
├── docs/
│   └── REFERENCE.md                 # This file
├── ca/                              # CA files (git-ignored)
│   ├── ca.key                       # Your CA private key
│   ├── ca.cer                       # Your CA certificate
│   └── ca.srl                       # Serial number file (auto-generated)
├── domains/                         # Generated .p12 files land here (git-ignored)
├── src/
│   └── s_certificate/               # Main package
│       ├── __init__.py
│       ├── __main__.py              # python -m s_certificate entry point
│       ├── cli.py                   # CLI argument parsing & main()
│       ├── config.py                # YAML config loader, validation, dataclasses
│       ├── openssl.py               # OpenSSL subprocess helpers, PEM/P12 generation
│       └── xc_upload.py             # F5 XC certificate upload via API
├── requirements.txt
└── README.md
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `cli.py` | Parses CLI arguments, loads config/domain list, orchestrates the CA check → generate → upload → package pipeline (single or batch) |
| `config.py` | Load and validate YAML config, typed dataclasses (`CertConfig`, `CAConfig`, `XCConfig`, `DistinguishedName`) |
| `openssl.py` | OpenSSL subprocess wrappers — CA generation, key generation, CSR creation, CA signing, P12 packaging, cleanup |
| `xc_upload.py` | F5 XC certificate API client — base64-encodes PEM files and POSTs to the XC certificate endpoint |

---

## Installation

For a quick platform-specific setup guide, see the [README](../README.md#1-install-dependencies).

### Prerequisites

- Python 3.9+
- OpenSSL (`/usr/bin/openssl` or configured path)
- A CA key and certificate — auto-generated on first run or created manually (see [Setup](../README.md#2-set-up-your-ca))
- For `--xc-upload`: an F5 Distributed Cloud tenant with API access and an API Token

### Install Steps

All commands assume you are in the project directory:

```bash
cd tools/s-certificate
```

A virtual environment is recommended:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate an API Token

Only required if you plan to use the `--xc-upload` flag to upload certificates to F5 XC.

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
./bin/run-s-certificate.sh --help
```

If you see `ModuleNotFoundError: No module named 'requests'` or similar, the dependencies are not installed. Re-run `pip install -r requirements.txt`.

---

## Configuration Reference

Copy the example file first:

```bash
cp config/config.yaml.example config/config.yaml
```

> **Security note:** `config/config.yaml` is git-ignored. Never commit your API token or credentials.

### Certificate Settings

```yaml
certificate:
  openssl_bin: "/usr/bin/openssl"
  key_size: 2048
  validity_days: 365
  ca_cert: "ca/ca.cer"
  ca_key: "ca/ca.key"
  output_dir: "domains"
  p12_password: ""
```

| Key | Default | Description |
|-----|---------|-------------|
| `openssl_bin` | `/usr/bin/openssl` | Path to the OpenSSL binary |
| `key_size` | `2048` | RSA key size in bits |
| `validity_days` | `365` | Certificate validity period in days |
| `ca_cert` | `ca/ca.cer` | CA certificate file (relative to project directory) |
| `ca_key` | `ca/ca.key` | CA private key file (relative to project directory) |
| `output_dir` | `domains` | Directory for generated files (relative to project directory) |
| `p12_password` | *(empty)* | Password for the `.p12` bundle. If set, OpenSSL uses it automatically (no prompt). If empty, OpenSSL prompts interactively. |

### CA Settings

```yaml
certificate:
  ca:
    key_size: 4096
    validity_days: 3650
    distinguished_name:    # optional — falls back to certificate.distinguished_name
      country: "XX"
      organization: "My Org CA"
```

| Key | Default | Description |
|-----|---------|-------------|
| `key_size` | `4096` | RSA key size for the CA key (recommend >= 4096) |
| `validity_days` | `3650` | CA certificate validity in days (~10 years) |
| `distinguished_name` | *(uses cert DN)* | Optional override for the CA subject. If omitted, the server cert DN is used. |

### Distinguished Name

```yaml
certificate:
  distinguished_name:
    country: "XX"
    state: "Your-State"
    locality: "Your-City"
    organization: "Your-Organization"
    organizational_unit: "Your-Unit"
    email: "your-email@example.com"
```

| Key | Default | Description |
|-----|---------|-------------|
| `country` | `XX` | Two-letter country code (ISO 3166-1 alpha-2) |
| `state` | `State` | State or province name |
| `locality` | `City` | City or locality name |
| `organization` | `Org` | Organization name |
| `organizational_unit` | `Unit` | Organizational unit name |
| `email` | `admin@example.com` | Email address |

### XC Settings

Used only when the `--xc-upload` flag is passed.

```yaml
xc:
  tenant: "acmecorp"
  api_token: "your-api-token"
  namespace: "default"
  cert_name_prefix: "lab-cert"
  cert_description: "Auto-generated server certificate for %s"
```

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `tenant` | Yes | — | XC tenant name (the part before `.console.ves.volterra.io`) |
| `api_token` | Yes | — | API token from F5 XC Console |
| `namespace` | No | `default` | Target namespace for the certificate object. Can be overridden with `--namespace / -n` on the CLI. |
| `cert_name_prefix` | No | `lab-cert` | Prefix for the certificate object name in XC |
| `cert_description` | No | `Auto-generated server certificate for %s` | Description template (`%s` = domain) |

The base URL (`https://{tenant}.console.ves.volterra.io`) and API endpoint path (`/api/config/namespaces/{ns}/certificates`) are hardcoded — these are fixed XC API patterns.

**Object naming:** The XC object name is built as `{prefix}-{domain}` with dots replaced by dashes, lowercased. Example: prefix `lab-cert` + domain `app.example.com` → `lab-cert-app-example-com`.

---

## CLI Options

The recommended way to run the tool is via the shell wrapper:

```bash
./bin/run-s-certificate.sh <domain> [options]
./bin/run-s-certificate.sh --domains <file> [options]
```

The wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

Alternatively, you can run it directly as a Python module:

```bash
PYTHONPATH=src python3 -m s_certificate <domain>
PYTHONPATH=src python3 -m s_certificate --domains <file>
```

```
positional arguments:
  domain                Domain name to generate a certificate for (optional if --domains is used)

options:
  --domains, -d FILE    Path to a file with domain names (one per line)
  --xc-upload, -xc      Upload the certificate to F5 Distributed Cloud after generation
  --namespace, -n       XC namespace override (requires --xc-upload; default: from config.yaml)
  --no-p12              Skip .p12 bundle creation (useful with --xc-upload when only uploading)
  --config, -c          Path to YAML config file (default: config/config.yaml)
```

**`--domains / -d`** reads a file with one domain per line (blank lines and `#` comments are skipped). Cannot be combined with a positional `domain` argument.

**`--xc-upload / -xc`** uploads each certificate to F5 XC after generation. Both flag names are accepted.

**`--namespace / -n`** overrides the `xc.namespace` value from `config.yaml` for a single run. This flag requires `--xc-upload` — using it without `--xc-upload` is an error.

### Domain List File

For batch processing, create a domain list file:

```bash
cp config/domains.txt.example config/domains.txt
```

Format:

```
# Comments start with #
# Blank lines are ignored

app.example.com
api.example.com
portal.example.com
```

The file is read once at startup. Each domain is processed in order. If a domain fails, processing continues with the remaining domains. The exit code is 1 if any domain failed, 0 if all succeeded.

---

## How the Tool Works

### Certificate Generation Pipeline

```
CLI  →  Config  →  CA Check  →  Generate Key  →  Create CSR  →  CA Sign  →  [XC Upload]  →  [P12 Bundle]  →  Cleanup
```

1. **Config** — load YAML, parse certificate settings, CA settings, and distinguished name
2. **CA check** — verify `ca/ca.key` and `ca/ca.cer` exist. If missing, prompt the user:
   - **`y`** — auto-generate a CA key + self-signed certificate using `certificate.ca` settings (key size, validity, DN), then continue
   - **`n` / Enter** — print manual CA creation commands and exit
3. **Generate key** — `openssl genrsa` creates an RSA private key (skipped if key already exists)
4. **Create CSR** — writes an OpenSSL config with the domain + wildcard SAN (`*.domain`), then runs `openssl req`
5. **CA sign** — `openssl x509 -req` signs the CSR with your CA certificate, producing the server cert
6. **XC upload** *(optional, `--xc-upload`)* — base64-encodes the PEM cert + key and POSTs to the XC certificate API
7. **P12 bundle** *(optional, skipped with `--no-p12`)* — `openssl pkcs12 -export` packages key + cert into a password-protected `.p12` file. If `p12_password` is set in config, it is passed via `-passout` (no prompt); otherwise OpenSSL prompts interactively
8. **Cleanup** — removes the intermediate PEM `.key` and `.cert` files

The XC upload happens **before** the P12 step and uses unencrypted PEM files directly — no passphrase is involved in the upload.

### CA Auto-Generation Details

When no CA is found, the tool offers to create one automatically. The auto-generated CA:

- Uses RSA with the configured key size (default: 4096 bit — stronger than server cert keys)
- Is a self-signed X.509 certificate valid for the configured period (default: 3650 days / ~10 years)
- Uses the distinguished name from `certificate.ca.distinguished_name` if set, otherwise falls back to the server certificate's `certificate.distinguished_name`
- Sets `CN` to `{organization} CA` automatically
- Writes to the configured `ca_cert` and `ca_key` paths (default: `ca/ca.cer`, `ca/ca.key`)
- Creates the `ca/` directory if it doesn't exist

For production or compliance use cases, create the CA manually with your own parameters — see [Option B in the README](../README.md#2-set-up-your-ca).

### XC Upload Details

When `--xc-upload` is used, the tool:

1. Reads the PEM certificate and private key from disk
2. Base64-encodes both and POSTs them to the XC certificate API
3. Creates a certificate object named `{prefix}-{domain}` (dots replaced with dashes, lowercase)
4. Uses `clear_secret_info` for the private key (suitable for lab/demo environments)
5. Then creates the `.p12` bundle (prompts for passphrase), unless `--no-p12` is set
6. Cleans up PEM files

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/config/namespaces/{ns}/certificates` | POST | Create a certificate object in XC |

### Request body

```json
{
  "metadata": {
    "name": "lab-cert-app-example-com",
    "namespace": "default",
    "description": "Auto-generated server certificate for app.example.com",
    "disable": false
  },
  "spec": {
    "certificate_url": "string:///<base64-encoded-PEM-cert>",
    "private_key": {
      "clear_secret_info": {
        "url": "string:///<base64-encoded-PEM-key>",
        "provider": ""
      }
    }
  }
}
```

Authentication: `Authorization: APIToken <token>` header on every request.

---

## Troubleshooting

### Common Errors

| Problem | Solution |
|---------|----------|
| `Config file not found` | Copy `config.yaml.example` to `config.yaml` and fill in your values |
| `XC tenant name not configured` | Set `xc.tenant` in `config/config.yaml` (required for `--xc-upload`) |
| `XC API token not configured` | Set `xc.api_token` in `config/config.yaml` (required for `--xc-upload`) |
| `Domain list file not found` | Copy `domains.txt.example` to `domains.txt` and fill in your domains |
| `Domain list file is empty` | Add at least one domain to your `domains.txt` file |
| `Provide either a domain argument or --domains, not both` | Use one or the other, not both at the same time |
| `401 Unauthorized` | API token is invalid or expired — regenerate it in F5 XC Console |
| `403 Forbidden` | Token lacks permissions for the namespace — check RBAC settings |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |

### OpenSSL Errors

| Problem | Solution |
|---------|----------|
| `openssl: command not found` | Install OpenSSL or update `certificate.openssl_bin` in config |
| `CA not found` | Run the tool and answer `y` to auto-generate, or create manually — see [Setup](../README.md#2-set-up-your-ca) |
| `unable to load CA certificate` | The CA cert file is corrupt or empty. Delete `ca/` and let the tool regenerate, or recreate manually. |
| `unable to load CA private key` | The CA key file is corrupt or empty. Delete `ca/` and let the tool regenerate, or recreate manually. |
| P12 passphrase prompt hangs | The `openssl pkcs12 -export` command prompts interactively for a passphrase. Set `certificate.p12_password` in config for automation, or use `--no-p12` to skip. |

### Python Environment

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'requests'` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'yaml'` | Run `pip install -r requirements.txt` (installs PyYAML) |
| `SyntaxError` on startup | Python 3.9+ is required. Check with `python3 --version`. |
| Permission denied on `run-s-certificate.sh` | Run `chmod +x bin/run-s-certificate.sh` |
| Virtual environment not activated | Run `source venv/bin/activate` before running the tool, or use `./bin/run-s-certificate.sh` which auto-activates it |
