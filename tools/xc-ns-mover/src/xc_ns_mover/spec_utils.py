"""
Utility functions for walking and rewriting XC API spec JSON structures.

These functions find and manipulate ``{name, namespace, tenant?}`` reference
dicts within deeply nested spec dictionaries.
"""

from __future__ import annotations

from typing import Any


# ------------------------------------------------------------------
# Heuristic mapping: reference path keywords -> API resource type
# ------------------------------------------------------------------

PATH_KEYWORD_TO_RESOURCE = {
    "pool": "origin_pools",
    "healthcheck": "healthchecks",
    "health_check": "healthchecks",
    "certificate": "certificates",
    "service_polic": "service_policys",
    "api_definition": "api_definitions",
    "app_firewall": "app_firewalls",
    "ip_prefix_set": "ip_prefix_sets",
    "rate_limiter": "rate_limiter_policys",
    "user_identification": "user_identifications",
}

# Namespaces that should never have their objects moved — these are
# system-managed or shared across tenants.
SKIP_NAMESPACES = frozenset({"system", "shared"})


def guess_resource_type(json_path: str) -> str | None:
    """Guess the XC API resource type from a JSON path containing a ref."""
    path_lower = json_path.lower()
    for keyword, resource in PATH_KEYWORD_TO_RESOURCE.items():
        if keyword in path_lower:
            return resource
    return None


def find_ns_refs(
    obj: Any, src_namespace: str, path: str = ""
) -> list[tuple[str, str, str]]:
    """Recursively find all {name, namespace, tenant?} reference dicts
    that point to *src_namespace*.

    Returns a list of (json_path, object_name, namespace).
    Only refs whose namespace matches src_namespace are included — we
    don't move objects from other namespaces (e.g. system/shared).
    Refs pointing to namespaces in SKIP_NAMESPACES are always excluded.
    """
    refs: list[tuple[str, str, str]] = []
    if isinstance(obj, dict):
        keys = set(obj.keys())
        # A ref dict looks like: {name, namespace} or {name, namespace, tenant}
        if "namespace" in keys and "name" in keys and keys <= {
            "name",
            "namespace",
            "tenant",
        }:
            ns = obj.get("namespace", "")
            if ns == src_namespace and ns not in SKIP_NAMESPACES:
                refs.append((path, obj["name"], ns))
        else:
            for k, v in obj.items():
                refs.extend(find_ns_refs(v, src_namespace, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            refs.extend(find_ns_refs(v, src_namespace, f"{path}[{i}]"))
    return refs


def rewrite_namespace_refs(
    obj: Any, src_namespace: str, dst_namespace: str
) -> Any:
    """Deep-copy *obj* and rewrite all {name, namespace, tenant?} reference
    dicts whose namespace == src_namespace to point to dst_namespace instead.
    """
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if "namespace" in keys and "name" in keys and keys <= {
            "name",
            "namespace",
            "tenant",
        }:
            out = dict(obj)
            if out.get("namespace") == src_namespace:
                out["namespace"] = dst_namespace
            return out
        return {k: rewrite_namespace_refs(v, src_namespace, dst_namespace) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [rewrite_namespace_refs(v, src_namespace, dst_namespace) for v in obj]
    return obj


def rewrite_name_refs(obj: Any, old_name: str, new_name: str, namespace: str) -> Any:
    """Deep-walk a spec dict and rewrite {name, namespace} reference dicts
    where name == old_name and namespace == namespace to use new_name instead.

    This updates internal JSON references when an object is renamed.
    """
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if "namespace" in keys and "name" in keys and keys <= {"name", "namespace", "tenant"}:
            if obj.get("name") == old_name and obj.get("namespace") == namespace:
                out = dict(obj)
                out["name"] = new_name
                return out
            return obj
        return {k: rewrite_name_refs(v, old_name, new_name, namespace) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [rewrite_name_refs(v, old_name, new_name, namespace) for v in obj]
    return obj


def rewrite_cert_ref(
    obj: Any, old_name: str, new_name: str, new_namespace: str,
) -> Any:
    """Rewrite a specific certificate ``{name, namespace}`` reference.

    Unlike :func:`rewrite_name_refs` (which only changes the name),
    this also rewrites the **namespace** — needed when a non-portable
    certificate is replaced by a matching cert in a different namespace
    (e.g. shared).
    """
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if "namespace" in keys and "name" in keys and keys <= {
            "name", "namespace", "tenant",
        }:
            if obj.get("name") == old_name:
                out = dict(obj)
                out["name"] = new_name
                out["namespace"] = new_namespace
                return out
            return obj
        return {
            k: rewrite_cert_ref(v, old_name, new_name, new_namespace)
            for k, v in obj.items()
        }
    elif isinstance(obj, list):
        return [
            rewrite_cert_ref(v, old_name, new_name, new_namespace)
            for v in obj
        ]
    return obj
