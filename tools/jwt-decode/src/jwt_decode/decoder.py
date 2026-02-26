"""
Core JWT decoding logic.

Decodes a JWT token without signature verification and returns the
header, payload, and raw signature as structured data.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass


@dataclass
class DecodedToken:
    """Holds the three decoded parts of a JWT token."""

    header: dict
    payload: dict
    signature: str


class DecodeError(Exception):
    """Raised when a JWT token cannot be decoded."""


def _add_base64_padding(data: str) -> str:
    """Add padding characters for base64url decoding."""
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    return data


def _decode_segment(segment: str, label: str) -> dict:
    """Decode a single base64url-encoded JWT segment into a dict."""
    try:
        b64 = _add_base64_padding(segment).replace("-", "+").replace("_", "/")
        raw = base64.b64decode(b64)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise DecodeError(f"Could not decode {label}: {exc}") from exc


def decode_token(token: str) -> DecodedToken:
    """
    Decode a JWT token string into its three components.

    The token is split on ``'.'`` and each segment is base64url-decoded.
    Signature verification is **not** performed — this is for inspection only.

    Raises:
        DecodeError: If the token is malformed or cannot be decoded.
    """
    token = token.strip()

    if not token:
        raise DecodeError("Token is empty.")

    parts = token.split(".")
    if len(parts) != 3:
        raise DecodeError(
            f"Invalid JWT format — expected 3 parts (header.payload.signature), "
            f"got {len(parts)}."
        )

    header = _decode_segment(parts[0], "header")
    payload = _decode_segment(parts[1], "payload")
    signature = parts[2]

    return DecodedToken(header=header, payload=payload, signature=signature)
