# S-Certificate — Self-Signed Certificate Generator

Generate server certificates signed by your own Certificate Authority (CA), with optional upload to F5 Distributed Cloud (XC).

| Command | What it does |
|---------|-------------|
| `./bin/run-s-certificate.sh <domain>` | Generate a `.p12` bundle for a domain |
| `./bin/run-s-certificate.sh <domain> --xc-upload` | Generate and upload to F5 XC |
| `./bin/run-s-certificate.sh <domain> --xc-upload --no-p12` | Upload to XC only (skip local `.p12`) |
| `./bin/run-s-certificate.sh --domains config/domains.txt` | Batch-generate from a domain list |
| `./bin/run-s-certificate.sh --domains config/domains.txt --xc-upload` | Batch-generate and upload all to XC |

Provide a domain name (or a file with multiple domains) and the tool produces a password-protected `.p12` (PKCS#12) bundle for each. Add `--xc-upload` to also push the certificates to your XC tenant as managed certificate objects.

Each generated certificate covers both the exact domain and all its subdomains (wildcard SAN).

---

## Things to consider

- The tool calls OpenSSL as a subprocess. Make sure `/usr/bin/openssl` (or your configured path) is available.

- A CA key and certificate are required. If none are found in the `ca/` directory, the tool will prompt to auto-generate one. You can also create a CA manually — see [Setup](#3-set-up-your-ca) below.

- The `.p12` export prompts interactively for a passphrase by default. Set `certificate.p12_password` in `config.yaml` to supply it automatically (required for batch/automation). Use `--no-p12` to skip `.p12` creation entirely.

- The XC upload uses `clear_secret_info` for the private key. This is suitable for lab/demo environments — not recommended for production.

- Re-creating a certificate in XC with the same name will fail (409 Conflict). Delete the existing object first or use a different prefix.

- API token expiration: the F5 XC API token has a limited lifetime. If the token expires during use, API calls will return 401. Ensure the token is still valid before running.

---

<h2 align="center">Setup</h2>
<p align="center"><em>Install dependencies, configure, set up a CA — then you're ready to go.</em></p>

---

## Quick Start

### 1. Install dependencies

All commands assume you are in the project directory:

```bash
cd tools/s-certificate
```

Make sure Python 3.9+ is installed. Install the system packages for your platform if needed:

<details>
<summary><strong>Linux (Debian/Ubuntu)</strong></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv openssl
```

</details>

<details>
<summary><strong>Linux (RHEL/Fedora)</strong></summary>

```bash
sudo dnf install python3 python3-pip openssl
```

</details>

<details>
<summary><strong>macOS</strong></summary>

macOS ships with Python 3 since Catalina (10.15) and includes LibreSSL.
If `python3 --version` shows nothing or a version below 3.9, install it via
[Homebrew](https://brew.sh):

```bash
brew install python@3 openssl
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

Make the shell wrapper executable (only needed once after cloning):

```bash
chmod +x bin/run-s-certificate.sh
```

<br>

Verify everything is working:

```bash
python3 --version          # must be 3.9+
pip show requests PyYAML   # both should be listed
openssl version            # OpenSSL must be available
```

<br>

### 2. Configure

Copy the example config:

```bash
cp config/config.yaml.example config/config.yaml
```

<br>

Edit `config/config.yaml` — the file has three sections:

**Server certificate** — fill in your subject fields (used for every certificate you generate):

```yaml
certificate:
  key_size: 2048
  validity_days: 365
  distinguished_name:
    country: "US"
    state: "California"
    organization: "My Lab"
```

**CA** — settings for auto-generating the CA (key size, validity, optional separate subject):

```yaml
  ca:
    key_size: 4096        # RSA key size for the CA
    validity_days: 3650   # ~10 years
```

**XC upload** *(optional — only needed with `--xc-upload`)*:

```yaml
xc:
  tenant: "acmecorp"
  api_token: "your-api-token"
  namespace: "default"
```

> **Security note:** `config/config.yaml` is git-ignored. Never commit your API token or credentials.

<br>

### 3. Set up your CA

The tool needs a Certificate Authority to sign server certificates. You have two options:

<details open>
<summary><strong>Option A: Auto-generate (recommended for lab/demo)</strong></summary>

Skip this step. When you run the tool for the first time without a CA, it detects the missing files and offers to create one using the settings from your `config.yaml`:

```
CA not found at: ca/ca.key, ca/ca.cer

The tool can auto-generate a CA for you, or you can create one manually.

  Auto-generate settings:
    Key size:    4096 bit
    Validity:    3650 days
    Subject:     C=ME, ST=Mordor, L=Barad-dur,
                 O=One Ring Authority, OU=Mount Doom Certificate Forge

Generate CA now? [y/N] y

Generating CA key (4096 bit)...
Generating CA certificate (valid 3650 days)...
CA created:
  Key:  ca/ca.key
  Cert: ca/ca.cer
```

The CA subject uses your `certificate.ca.distinguished_name` values if configured, otherwise it falls back to `certificate.distinguished_name`. See `config.yaml.example` for both options.

After generation, the tool continues with the certificate request automatically.

</details>

<details>
<summary><strong>Option B: Create manually</strong></summary>

If you prefer full control over the CA (e.g. for a specific subject, key type, or passphrase-protected key):

```bash
mkdir -p ca
openssl genrsa -out ca/ca.key 4096
openssl req -new -x509 -days 3650 -key ca/ca.key -out ca/ca.cer
```

OpenSSL will prompt for the CA subject fields interactively. After this, the tool will find the CA and skip the auto-generation prompt.

If you already have a CA from another source, place the files at the configured paths (`ca/ca.key` and `ca/ca.cer` by default, configurable in `config.yaml`).

</details>

<br>

### 4. Get an API Token (optional — only for `--xc-upload`)

1. Log into your F5 XC Console
2. Go to **Administration → Credentials → API Credentials**
3. Click **Create Credentials** → select **API Token** → **Generate**
4. Copy the token

---

<h2 align="center">Usage</h2>
<p align="center"><em>Generate certificates, upload to XC, bundle as .p12.</em></p>

---

## Running the tool

### Single domain

```bash
./bin/run-s-certificate.sh myapp.example.com
```

### Batch mode (multiple domains)

Create a domain list file (one domain per line):

```bash
cp config/domains.txt.example config/domains.txt
```

Edit `config/domains.txt`:

```
app.example.com
api.example.com
portal.example.com
```

Then run:

```bash
./bin/run-s-certificate.sh --domains config/domains.txt
```

The tool processes each domain in order and prints a summary at the end:

```
Processing 3 domains...

Generating certificate for: app.example.com
  ...
Generating certificate for: api.example.com
  ...
Generating certificate for: portal.example.com
  ...

Done — 3/3 succeeded.
```

If a domain fails, the tool continues with the remaining domains and exits with code 1.

> **Tip:** For batch mode, set `certificate.p12_password` in `config.yaml` to avoid being prompted for a passphrase on every domain. Or use `--no-p12` to skip `.p12` creation entirely.

<br>

The shell wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

<details>
<summary><strong>Alternative: run as Python module directly</strong></summary>

If you prefer not to use the shell wrapper:

```bash
source venv/bin/activate
PYTHONPATH=src python3 -m s_certificate myapp.example.com
```

</details>

<br>

### Examples

```bash
# Single domain — generate .p12 bundle
./bin/run-s-certificate.sh myapp.example.com

# Single domain — generate and upload to F5 XC
./bin/run-s-certificate.sh myapp.example.com --xc-upload

# Single domain — upload to a specific namespace (overrides config.yaml)
./bin/run-s-certificate.sh myapp.example.com --xc-upload --namespace production

# Single domain — upload to XC only, skip .p12
./bin/run-s-certificate.sh myapp.example.com --xc-upload --no-p12

# Batch — generate .p12 bundles for all domains in the list
./bin/run-s-certificate.sh --domains config/domains.txt

# Batch — generate and upload all to XC, skip .p12
./bin/run-s-certificate.sh --domains config/domains.txt --xc-upload --no-p12

# Use a custom config file
./bin/run-s-certificate.sh myapp.example.com --config /path/to/config.yaml
```

<br>

<details>
<summary><strong>Options</strong></summary>

| Flag | Description |
|------|-------------|
| `--domains, -d` | Path to a file with domain names, one per line (alternative to positional `domain`) |
| `--xc-upload, -xc` | Upload the certificate to F5 Distributed Cloud after generation |
| `--namespace, -n` | XC namespace override (requires `--xc-upload`; default: from config.yaml) |
| `--no-p12` | Skip .p12 bundle creation (useful with `--xc-upload` when only uploading) |
| `--config, -c` | Path to YAML config file (default: `config/config.yaml`) |

</details>

---

<h2 align="center">Reference</h2>
<p align="center"><em>Troubleshooting and further documentation.</em></p>

---

## Common Issues

| Problem | Fix |
|---------|-----|
| `Config file not found` | Run `cp config/config.yaml.example config/config.yaml` |
| `Domain list file not found` | Run `cp config/domains.txt.example config/domains.txt` |
| `CA not found` | Run the tool and answer `y` to auto-generate, or create manually — see [Setup](#3-set-up-your-ca) |
| `--namespace requires --xc-upload` | The `-n` flag only works when uploading to XC |
| `Provide either a domain argument or --domains, not both` | Use one or the other, not both at the same time |
| `XC tenant name not configured` | Set `xc.tenant` in `config/config.yaml` |
| `XC API token not configured` | Set `xc.api_token` in `config/config.yaml` |
| `401 Unauthorized` | API token is invalid or expired — regenerate it |
| `Permission denied on run-s-certificate.sh` | Run `chmod +x bin/run-s-certificate.sh` |
| `Connection error` | Verify tenant name and network connectivity to F5 XC |

---

For project structure, module architecture, config reference, API details, and extended troubleshooting — see the **[Reference Guide](docs/REFERENCE.md)**.
