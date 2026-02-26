# JWT Decode — Reference Guide

Detailed technical documentation for the jwt-decode tool. For a quick-start guide, see the [README](../README.md).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Installation](#installation)
- [CLI Options](#cli-options)
- [How the Tool Works](#how-the-tool-works)
  - [Decoding Pipeline](#decoding-pipeline)
  - [Base64url Handling](#base64url-handling)
- [Troubleshooting](#troubleshooting)

---

## Project Structure

```
jwt-decode/
├── bin/
│   └── run-jwt-decode.sh            # Shell wrapper — auto-activates venv
├── docs/
│   └── REFERENCE.md                 # This file
├── src/
│   └── jwt_decode/                  # Main package
│       ├── __init__.py
│       ├── __main__.py              # python -m jwt_decode entry point
│       ├── cli.py                   # CLI argument parsing, output formatting, main()
│       └── decoder.py               # Core decoding logic (no external dependencies)
├── requirements.txt
├── .gitignore
└── README.md
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `cli.py` | Parses CLI arguments, resolves token input (interactive prompt, argument, or stdin), formats and prints the decoded output |
| `decoder.py` | Pure decoding logic — splits the token, base64url-decodes header and payload, returns a structured `DecodedToken` dataclass |

---

## Installation

For a quick platform-specific setup guide, see the [README](../README.md#1-install-dependencies).

### Prerequisites

- Python 3.9+
- No external packages — the tool uses only the Python standard library (`base64`, `json`, `argparse`, `dataclasses`)

### Install Steps

All commands assume you are in the project directory:

```bash
cd tools/jwt-decode
```

A virtual environment is optional (there are no pip dependencies), but recommended for consistency with the other tools in this repo:

```bash
python3 -m venv venv
source venv/bin/activate
```

### Verify Installation

```bash
python3 --version    # must be 3.9+
./bin/run-jwt-decode.sh --help
```

---

## CLI Options

The recommended way to run the tool is via the shell wrapper:

```bash
./bin/run-jwt-decode.sh [token] [options]
```

The wrapper auto-activates the virtual environment (if present) and sets the correct `PYTHONPATH`. All CLI flags are passed through.

Alternatively, you can run it directly as a Python module:

```bash
PYTHONPATH=src python3 -m jwt_decode [token] [options]
```

```
positional arguments:
  token       JWT token string (optional — prompts interactively if omitted)

options:
  --stdin     Read token from stdin (for piping)
  --help, -h  Show help message and exit
```

### Input Modes

| Mode | How to use | When |
|------|-----------|------|
| **Interactive** | `./bin/run-jwt-decode.sh` | Quick manual inspection — the tool prompts for a token |
| **Argument** | `./bin/run-jwt-decode.sh <token>` | Scripting or one-liners |
| **Stdin** | `echo '<token>' \| ./bin/run-jwt-decode.sh --stdin` | Piping from another command |

---

## How the Tool Works

### Decoding Pipeline

```
Input  →  Validate (3-part structure)  →  Decode Header  →  Decode Payload  →  Extract Signature  →  Print
```

1. **Input** — token is received via interactive prompt, CLI argument, or stdin
2. **Validate** — split on `.` and verify exactly 3 parts exist
3. **Decode header** — base64url-decode the first segment, parse as JSON
4. **Decode payload** — base64url-decode the second segment, parse as JSON
5. **Extract signature** — the third segment is kept as-is (base64url-encoded)
6. **Print** — header and payload are pretty-printed as indented JSON; signature is printed as the raw base64url string

Signature verification is **not** performed. This tool is for inspection only — use a proper JWT library with key material for token validation.

### Base64url Handling

JWT segments use base64url encoding (RFC 4648 §5), which differs from standard base64:

| Standard base64 | base64url |
|-----------------|-----------|
| `+` | `-` |
| `/` | `_` |
| `=` padding required | Padding omitted |

The decoder converts base64url back to standard base64 by replacing `-` → `+` and `_` → `/`, then adds any missing `=` padding before calling Python's `base64.b64decode()`.

---

## Troubleshooting

### Common Errors

| Problem | Solution |
|---------|----------|
| `Invalid JWT format — expected 3 parts` | The input is not a valid JWT. A JWT must have exactly three dot-separated segments (`header.payload.signature`). |
| `Could not decode header` / `Could not decode payload` | The segment is not valid base64url-encoded JSON. The token may be truncated or corrupted. |
| `Token is empty` | No token was provided. Check your input or stdin pipe. |
| `No token received on stdin` | `--stdin` was used but nothing was piped. Ensure the upstream command produces output. |

### Python Environment

| Problem | Solution |
|---------|----------|
| `SyntaxError` on startup | Python 3.9+ is required. Check with `python3 --version`. |
| `ModuleNotFoundError: No module named 'jwt_decode'` | Run the tool via `./bin/run-jwt-decode.sh` (sets `PYTHONPATH` automatically), or set `PYTHONPATH=src` manually. |
| Permission denied on `run-jwt-decode.sh` | Run `chmod +x bin/run-jwt-decode.sh` |
| Virtual environment not activated | Run `source venv/bin/activate` before running the tool, or use `./bin/run-jwt-decode.sh` which auto-activates it |

### Migration from Previous Version

The previous version (`jwt-decode.py`) used the `PyJWT` library and was a single flat script. The refactored version:

- **No longer requires PyJWT** — decoding is done with the Python standard library only
- Uses the same project structure as all other tools in this repo (`bin/`, `src/`, `docs/`)
- Supports three input modes: interactive prompt, CLI argument, and stdin pipe
- Can be run as a Python module: `python -m jwt_decode`
