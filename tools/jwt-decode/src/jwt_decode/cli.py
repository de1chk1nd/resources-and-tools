"""
CLI entry point for the JWT Decode tool.

Provides both interactive mode (prompt for token) and argument mode
(pass token directly or pipe via stdin).
"""

from __future__ import annotations

import argparse
import json
import sys

from .decoder import DecodeError, decode_token

__all__ = ["main"]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _print_json(label: str, data: dict) -> None:
    """Print a labelled JSON section."""
    print(f"\n{label}:")
    print(json.dumps(data, indent=4))


def _print_result(header: dict, payload: dict, signature: str) -> None:
    """Pretty-print the decoded token parts."""
    _print_json("Header", header)
    _print_json("Payload", payload)
    print(f"\nSignature (base64url encoded):\n{signature}")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode and inspect a JWT token without signature verification.",
        epilog="Examples:\n"
               "  %(prog)s                          # interactive prompt\n"
               "  %(prog)s <token>                   # pass token as argument\n"
               "  echo '<token>' | %(prog)s --stdin  # read from stdin\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "token",
        nargs="?",
        default=None,
        help="JWT token string (optional — prompts interactively if omitted)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        default=False,
        help="Read token from stdin (for piping)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    # --- Resolve token input -----------------------------------------------
    if args.stdin:
        token = sys.stdin.read().strip()
        if not token:
            print("Error: No token received on stdin.")
            sys.exit(1)
    elif args.token:
        token = args.token
    else:
        # Interactive mode
        print("JWT Token Decoder")
        print("=================")
        try:
            token = input("Please enter your JWT token: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)

    # --- Decode -------------------------------------------------------------
    try:
        result = decode_token(token)
    except DecodeError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    _print_result(result.header, result.payload, result.signature)
