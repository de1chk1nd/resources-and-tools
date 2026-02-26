"""
Input validation and sanitization for user-supplied values.

Prevents query injection (LogQL), path traversal, and XSS in report output.
"""

from __future__ import annotations

import re
import logging

__all__ = [
    "ValidationError",
    "sanitize_query_value",
    "sanitize_req_id",
    "sanitize_src_ip",
    "sanitize_fqdn",
    "sanitize_lb_name",
    "sanitize_namespace",
    "sanitize_tenant",
    "escape_markdown",
]

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when user input fails validation."""


# ---------------------------------------------------------------------------
# LogQL / query value sanitisation
# ---------------------------------------------------------------------------

# Characters that could break LogQL query syntax or inject operators.
_LOGQL_UNSAFE = re.compile(r'["{}\n\r\\]')

# Load balancer names may contain alphanumerics, hyphens, underscores, dots.
_LB_PATTERN = re.compile(r'^[\w.\-]+$')

# Namespace: typically alphanumerics and hyphens.
_NS_PATTERN = re.compile(r'^[\w\-]+$')

# Tenant: alphanumerics, hyphens, underscores.
_TENANT_PATTERN = re.compile(r'^[\w\-]+$')

# IP address (v4 loose — just block obvious nonsense, not a strict RFC check).
_IPV4_LOOSE = re.compile(r'^[\d.:a-fA-F]+$')

# UUID-ish request IDs: hex, hyphens, some implementations add extra chars.
_REQID_PATTERN = re.compile(r'^[\w\-.:]+$')

# FQDN: labels separated by dots.
_FQDN_PATTERN = re.compile(r'^[\w.\-]+$')


def sanitize_query_value(value: str, field_name: str) -> str:
    """Validate a value before embedding it in a LogQL exact-match filter.

    Rejects values containing characters that could break or escape the
    ``field="value"`` syntax used by the F5 XC query API.

    Returns the value unchanged if valid; raises ``ValidationError`` otherwise.
    """
    value = value.strip()
    if not value:
        return value

    if _LOGQL_UNSAFE.search(value):
        raise ValidationError(
            f"Invalid characters in {field_name}: {value!r}. "
            f'Values must not contain quotes, braces, backslashes, or newlines.'
        )
    return value


def sanitize_req_id(value: str) -> str:
    """Validate a request ID."""
    value = value.strip()
    if not value:
        return value
    if not _REQID_PATTERN.match(value):
        raise ValidationError(
            f"Invalid request ID format: {value!r}. "
            "Expected UUID or alphanumeric identifier."
        )
    return sanitize_query_value(value, "request ID")


def sanitize_src_ip(value: str) -> str:
    """Validate a source IP address."""
    value = value.strip()
    if not value:
        return value
    if not _IPV4_LOOSE.match(value):
        raise ValidationError(
            f"Invalid source IP format: {value!r}. "
            "Expected an IPv4 or IPv6 address."
        )
    return sanitize_query_value(value, "source IP")


def sanitize_fqdn(value: str) -> str:
    """Validate an FQDN / hostname."""
    value = value.strip()
    if not value:
        return value
    if not _FQDN_PATTERN.match(value):
        raise ValidationError(
            f"Invalid FQDN format: {value!r}. "
            "Expected a hostname like 'api.example.com'."
        )
    if len(value) > 253:
        raise ValidationError(f"FQDN too long ({len(value)} chars, max 253).")
    return sanitize_query_value(value, "FQDN")


def sanitize_lb_name(value: str) -> str:
    """Validate a load balancer name (used in regex match)."""
    value = value.strip()
    if not value:
        return value
    if not _LB_PATTERN.match(value):
        raise ValidationError(
            f"Invalid load balancer name: {value!r}. "
            "Expected alphanumerics, hyphens, underscores, or dots only."
        )
    if len(value) > 256:
        raise ValidationError(f"Load balancer name too long ({len(value)} chars, max 256).")
    return value


def sanitize_namespace(value: str) -> str:
    """Validate a namespace name."""
    value = value.strip()
    if not value:
        return value
    if not _NS_PATTERN.match(value):
        raise ValidationError(
            f"Invalid namespace: {value!r}. "
            "Expected alphanumerics, hyphens, or underscores."
        )
    return value


def sanitize_tenant(value: str) -> str:
    """Validate a tenant name (used in URL construction)."""
    value = value.strip()
    if not value:
        return value
    if not _TENANT_PATTERN.match(value):
        raise ValidationError(
            f"Invalid tenant name: {value!r}. "
            "Expected alphanumerics, hyphens, or underscores."
        )
    return value


# ---------------------------------------------------------------------------
# Markdown escaping
# ---------------------------------------------------------------------------

# Characters with special meaning in Markdown (GFM).
_MD_SPECIAL = re.compile(r'([\\`*_{}[\]()#+\-.!|~>])')


def escape_markdown(text: str) -> str:
    """Escape special Markdown characters in user-controlled text.

    This prevents accidental formatting or HTML injection when Markdown
    is rendered in contexts that support inline HTML (GitHub, Jira, etc.).
    """
    if not text or text == "N/A":
        return text
    # Escape the backslash first, then other specials.
    return _MD_SPECIAL.sub(r'\\\1', str(text))
