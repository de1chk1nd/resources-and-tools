# S-Certificate — Self-Signed Certificate Generator

Generates server certificates signed by your own Certificate Authority (CA), with optional upload to F5 Distributed Cloud (XC).

Provide a domain name and the script produces a `.p12` (PKCS#12) bundle. Add `--xc` to also push the certificate to your XC tenant as a managed certificate object.

The generated certificate covers both the exact domain and all its subdomains (wildcard SAN).

## What it does

1. Generates a server private key (RSA, configurable key size)
2. Creates a CSR with the domain and `*.domain` as Subject Alternative Names
3. Signs the CSR with your CA certificate
4. *(optional)* Uploads the PEM certificate and key to F5 XC via API (`--xc`)
5. *(optional)* Packages key + cert into a password-protected `.p12` bundle (skipped with `--no-p12`)
6. Cleans up PEM and intermediate files

The XC upload uses the unencrypted PEM files directly and happens **before** the `.p12` step, so no passphrase is involved in the upload.

## Project Structure

```
s-certificate/
├── ca/                         # CA files (git-ignored)
│   ├── ca.key                  # Your CA private key
│   ├── ca.cer                  # Your CA certificate
│   └── ca.srl                  # Serial number file (auto-generated)
├── domains/                    # Generated .p12 files land here (git-ignored)
├── etc/
│   ├── config.yaml             # Your local config (git-ignored)
│   └── config.yaml.bk          # Template — copy and edit
├── generate_s-cert.py          # Main script
└── README.md
```

## Prerequisites

- Python 3.x
- OpenSSL (`/usr/bin/openssl`)
- A CA key and certificate (see below)
- For `--xc`: [PyYAML](https://pypi.org/project/PyYAML/) and [requests](https://pypi.org/project/requests/)

```bash
pip install pyyaml requests
```

## Setup

### 1. Create your CA key and certificate

```bash
mkdir -p ca
openssl genrsa -out ca/ca.key 4096
openssl req -new -x509 -days 3650 -key ca/ca.key -out ca/ca.cer
```

### 2. Create your config file

```bash
cp etc/config.yaml.bk etc/config.yaml
```

Edit `etc/config.yaml` with your values. The config controls:

- **Certificate settings** — key size, validity, CA file paths, distinguished name fields
- **XC settings** — tenant, API token, namespace, naming conventions

> **Security note:** `etc/config.yaml` is git-ignored. Never commit your API token or credentials.

## Usage

### Local-only (generate .p12)

```bash
python generate_s-cert.py myapp.example.com
```

### Generate and upload to F5 XC

```bash
python generate_s-cert.py myapp.example.com --xc
```

### Upload to XC only (skip local .p12)

```bash
python generate_s-cert.py myapp.example.com --xc --no-p12
```

### Use a custom config file

```bash
python generate_s-cert.py myapp.example.com --xc --config /path/to/config.yaml
```

### All CLI options

```
positional arguments:
  domain                Domain name to generate a certificate for

options:
  --xc                  Upload the certificate to F5 Distributed Cloud after generation
  --no-p12              Skip .p12 bundle creation (useful with --xc when only uploading)
  --config, -c          Path to YAML config file (default: etc/config.yaml)
```

## Configuration Reference

All settings are in `etc/config.yaml`. See `etc/config.yaml.bk` for the full template with comments.

### Certificate section

| Key | Description | Default |
|-----|-------------|---------|
| `openssl_bin` | Path to the OpenSSL binary | `/usr/bin/openssl` |
| `key_size` | RSA key size in bits | `2048` |
| `validity_days` | Certificate validity period | `365` |
| `ca_cert` | CA certificate file (relative to script dir) | `ca/ca.cer` |
| `ca_key` | CA private key file (relative to script dir) | `ca/ca.key` |
| `output_dir` | Directory for generated files | `domains` |
| `distinguished_name.*` | CSR subject fields (country, state, org, etc.) | — |

### XC section (used with `--xc`)

| Key | Description | Default |
|-----|-------------|---------|
| `tenant` | XC tenant name | — |
| `api_token` | API token for authentication | — |
| `api_url_template` | Base URL pattern (`%s` = tenant) | `https://%s.console.ves.volterra.io` |
| `namespace` | Target namespace for the certificate | `default` |
| `api_endpoint` | API path (`%s` = namespace) | `/api/config/namespaces/%s/certificates` |
| `cert_name_prefix` | Object name prefix in XC | `lab-cert` |
| `cert_description` | Description template (`%s` = domain) | `Auto-generated server certificate for %s` |

## XC Upload Details

When `--xc` is used, the tool:

1. Generates the PEM certificate and private key
2. Base64-encodes both and POSTs them to the XC certificate API (no passphrase involved)
3. Creates a certificate object named `{prefix}-{domain}` (dots replaced with dashes, lowercase)
4. Uses `clear_secret_info` for the private key (suitable for lab/demo environments)
5. Then creates the `.p12` bundle (prompts for passphrase), unless `--no-p12` is set
6. Cleans up PEM files

### XC API endpoint

```
POST https://{tenant}.console.ves.volterra.io/api/config/namespaces/{namespace}/certificates
Authorization: APIToken {token}
```

### Generate an API Token

1. Log into your F5 XC Console
2. Navigate to **Administration > Credentials > API Credentials**
3. Click **Create Credentials**
4. Select **API Token** as the credential type
5. Set an expiry and click **Generate**
6. Copy the token value
