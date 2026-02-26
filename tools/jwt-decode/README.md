# JWT Decode — JWT Token Inspector

Decode and inspect JWT (JSON Web Token) tokens without signature verification. Useful for quickly examining token contents during debugging and troubleshooting.

| Command | What it does |
|---------|-------------|
| `./bin/run-jwt-decode.sh` | Interactive — prompts for a token |
| `./bin/run-jwt-decode.sh <token>` | Decode a token passed as argument |
| `echo '<token>' \| ./bin/run-jwt-decode.sh --stdin` | Decode a token piped via stdin |

Paste or pipe a JWT and the tool pretty-prints the **header**, **payload**, and **signature** as separate sections.

---

## Things to consider

- Signature verification is **skipped** — this tool is for inspection only, not for validating token authenticity. Use a proper JWT library with key material for validation.

- The token must be a valid 3-part JWT (`header.payload.signature`). Tokens with fewer or more segments are rejected.

- No external dependencies — the tool uses only the Python standard library.

---

<h2 align="center">Setup</h2>
<p align="center"><em>Install Python, run the tool — that's it.</em></p>

---

## Quick Start

### 1. Install dependencies

All commands assume you are in the project directory:

```bash
cd tools/jwt-decode
```

Make sure Python 3.9+ is installed. Install the system packages for your platform if needed:

<details>
<summary><strong>Linux (Debian/Ubuntu)</strong></summary>

```bash
sudo apt update
sudo apt install python3 python3-venv
```

</details>

<details>
<summary><strong>Linux (RHEL/Fedora)</strong></summary>

```bash
sudo dnf install python3
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

A virtual environment is optional (there are no pip dependencies), but recommended for consistency:

```bash
python3 -m venv venv
source venv/bin/activate
```

<br>

Make the shell wrapper executable (only needed once after cloning):

```bash
chmod +x bin/run-jwt-decode.sh
```

<br>

Verify everything is working:

```bash
python3 --version              # must be 3.9+
./bin/run-jwt-decode.sh --help
```

---

<h2 align="center">Usage</h2>
<p align="center"><em>Decode tokens interactively, as arguments, or from a pipe.</em></p>

---

## Running the tool

### Interactive mode

```bash
./bin/run-jwt-decode.sh
```

The tool prompts for a token, then prints the decoded output.

### Pass token as argument

```bash
./bin/run-jwt-decode.sh "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Pipe via stdin

```bash
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." | ./bin/run-jwt-decode.sh --stdin
```

<br>

The shell wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

<details>
<summary><strong>Alternative: run as Python module directly</strong></summary>

If you prefer not to use the shell wrapper:

```bash
source venv/bin/activate
PYTHONPATH=src python3 -m jwt_decode
```

</details>

<br>

### Examples

```bash
# Interactive — prompts for a token
./bin/run-jwt-decode.sh

# Decode a token passed as argument
./bin/run-jwt-decode.sh "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Pipe from another command
cat /tmp/token.txt | ./bin/run-jwt-decode.sh --stdin

# Pipe from curl
curl -s https://example.com/api/token | jq -r '.access_token' | ./bin/run-jwt-decode.sh --stdin
```

<br>

### Example output

```
Header:
{
    "alg": "RS256",
    "typ": "JWT"
}

Payload:
{
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}

Signature (base64url encoded):
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

<br>

<details>
<summary><strong>Options</strong></summary>

| Flag | Description |
|------|-------------|
| `token` | JWT token string (positional, optional — prompts interactively if omitted) |
| `--stdin` | Read token from stdin instead of prompt or argument |
| `--help, -h` | Show help message and exit |

</details>

---

<h2 align="center">Reference</h2>
<p align="center"><em>Troubleshooting and further documentation.</em></p>

---

## Common Issues

| Problem | Fix |
|---------|-----|
| `Invalid JWT format — expected 3 parts` | The input is not a valid JWT. Ensure it has three dot-separated segments. |
| `Could not decode header/payload` | The token may be truncated or corrupted. |
| `Token is empty` | No token was provided — check your input. |
| `No token received on stdin` | `--stdin` was used but nothing was piped. |
| `Permission denied on run-jwt-decode.sh` | Run `chmod +x bin/run-jwt-decode.sh` |

---

For project structure, module architecture, and extended troubleshooting — see the **[Reference Guide](docs/REFERENCE.md)**.
