"""
Name conflict resolution for the mover subcommand.

When an object with the same name already exists in the target namespace,
the user can choose to skip the object or rename it by prepending a
configurable prefix.
"""

from __future__ import annotations


__all__ = [
    "make_prefixed_name",
    "resolve_conflict",
]


def make_prefixed_name(prefix: str, name: str) -> str:
    """Build a prefixed name: ``'<prefix>-<name>'``."""
    return f"{prefix}-{name}"


def _resolve_conflict_interactive(
    object_desc: str,
    original_name: str,
    prefix: str,
) -> str | None:
    """Prompt the user to resolve a naming conflict interactively.

    Returns:
        The new name (with prefix) if the user chose to rename,
        or None if the user chose to skip.
    """
    new_name = make_prefixed_name(prefix, original_name)
    print(f"    CONFLICT: {object_desc} '{original_name}' already exists in target namespace.")
    print(f"      [s] Skip this object")
    print(f"      [r] Rename to '{new_name}'")
    while True:
        answer = input("      Choose [s/r]: ").strip().lower()
        if answer in ("s", "skip"):
            return None
        if answer in ("r", "rename"):
            return new_name


def resolve_conflict(
    object_desc: str,
    original_name: str,
    prefix: str,
    conflict_action: str,
) -> str | None:
    """Resolve a naming conflict based on the conflict action policy.

    Args:
        object_desc: Human-readable description (e.g. "HTTP LB", "Origin Pool 'my-pool'")
        original_name: Original object name
        prefix: The conflict prefix from config
        conflict_action: One of "ask", "skip", "prefix"

    Returns:
        The new name (with prefix) if the object should be renamed,
        or None if the object should be skipped.
    """
    new_name = make_prefixed_name(prefix, original_name)

    if conflict_action == "skip":
        print(f"    CONFLICT: {object_desc} '{original_name}' already exists — skipping (--conflict-action=skip)")
        return None

    if conflict_action == "prefix":
        print(f"    CONFLICT: {object_desc} '{original_name}' already exists — renaming to '{new_name}' (--conflict-action=prefix)")
        return new_name

    # conflict_action == "ask"
    return _resolve_conflict_interactive(object_desc, original_name, prefix)
