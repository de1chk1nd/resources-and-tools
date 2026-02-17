# JWT Decode

Interactive CLI tool that decodes and inspects JWT (JSON Web Token) tokens without signature verification. Useful for quickly examining token contents during debugging and troubleshooting.

## What it does

1. Prompts for a JWT token string
2. Decodes the token without signature verification
3. Pretty-prints the header, payload, and signature separately

## Prerequisites

- Python 3.x
- [PyJWT](https://pypi.org/project/PyJWT/)

## Setup

```bash
pip install PyJWT
```

## Usage

```bash
python jwt-decode.py
```

The script will prompt you to paste a JWT token, then output:

- **Decoded token** — full payload as JSON
- **Header** — algorithm, token type, key ID, etc.
- **Payload** — claims (issuer, subject, expiry, custom claims, etc.)
- **Signature** — base64url-encoded signature string

### Example output

```
JWT Token Decoder
=================
Please enter your JWT token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Decoded JWT Token (without verification):
{
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}

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

## Notes

- Signature verification is **skipped** — this tool is for inspection only, not for validating token authenticity.
- The token must be a valid 3-part JWT (`header.payload.signature`).
