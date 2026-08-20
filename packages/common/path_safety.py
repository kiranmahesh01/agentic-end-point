"""Path safety utilities to prevent directory traversal and symlink escapes."""

import os
from pathlib import Path


def canonicalize_path(path: str, base: str | None = None) -> str:
    """
    Canonicalize a path to its absolute, normalized form.

    Args:
        path: The path to canonicalize
        base: Optional base directory to resolve relative paths against

    Returns:
        Absolute, normalized path with symlinks resolved.
    """
    if base:
        path = os.path.join(base, path)

    return os.path.realpath(os.path.normpath(os.path.abspath(path)))


def is_path_safe(path: str) -> tuple[bool, str]:
    """
    Check if a path is safe (no traversal attempts).

    Returns:
        Tuple of (is_safe, reason)
    """
    if ".." in path:
        return False, "Path contains directory traversal (..) component"

    normalized = os.path.normpath(path)
    if ".." in normalized:
        return False, "Normalized path still contains traversal"

    if path.startswith("~"):
        return False, "Path contains home directory expansion"

    dangerous_patterns = [
        "/etc/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/root/",
    ]

    for pattern in dangerous_patterns:
        if path.startswith(pattern):
            return False, f"Path targets sensitive directory: {pattern}"

    return True, "Path is safe"


def is_within_roots(path: str, allowed_roots: list[str]) -> tuple[bool, str]:
    """
    Check if a canonicalized path is within any of the allowed root directories.

    Args:
        path: The path to check (should already be canonicalized)
        allowed_roots: List of allowed root directories

    Returns:
        Tuple of (is_within, reason)
    """
    if not allowed_roots:
        return False, "No allowed roots configured"

    canonical_path = canonicalize_path(path)

    for root in allowed_roots:
        canonical_root = canonicalize_path(root)
        try:
            Path(canonical_path).relative_to(canonical_root)
            return True, f"Path is within allowed root: {root}"
        except ValueError:
            continue

    return False, f"Path {canonical_path} is not within any allowed root: {allowed_roots}"


def check_symlink_escape(path: str, allowed_roots: list[str]) -> tuple[bool, str]:
    """
    Check if a path escapes allowed roots via symlink.

    Args:
        path: The path to check
        allowed_roots: List of allowed root directories

    Returns:
        Tuple of (is_safe, reason)
    """
    try:
        real_path = os.path.realpath(path)
    except (OSError, ValueError) as e:
        return False, f"Cannot resolve path: {e}"

    is_within, reason = is_within_roots(real_path, allowed_roots)

    if not is_within:
        original_abs = os.path.abspath(path)
        if original_abs != real_path:
            return False, f"Symlink escape detected: {path} resolves to {real_path}"
        return False, reason

    return True, "Path is safe (no symlink escape)"


def validate_path_for_operation(
    path: str,
    operation: str,
    read_roots: list[str],
    write_roots: list[str],
) -> tuple[bool, str]:
    """
    Validate a path for a specific operation.

    Args:
        path: The path to validate
        operation: The operation type (read_file, write_file, etc.)
        read_roots: Allowed roots for read operations
        write_roots: Allowed roots for write operations

    Returns:
        Tuple of (is_valid, reason)
    """
    is_safe, reason = is_path_safe(path)
    if not is_safe:
        return False, reason

    canonical = canonicalize_path(path)

    if operation == "read_file":
        is_within, reason = is_within_roots(canonical, read_roots)
        if not is_within:
            return False, f"Read not allowed: {reason}"

        symlink_safe, symlink_reason = check_symlink_escape(path, read_roots)
        if not symlink_safe:
            return False, symlink_reason

    elif operation == "write_file":
        is_within, reason = is_within_roots(canonical, write_roots)
        if not is_within:
            return False, f"Write not allowed: {reason}"

        symlink_safe, symlink_reason = check_symlink_escape(path, write_roots)
        if not symlink_safe:
            return False, symlink_reason

    return True, "Path is valid for operation"
