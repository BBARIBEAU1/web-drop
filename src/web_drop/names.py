"""Filename rules for the flat drop directory.

Uploads are stored next to each other in one directory. Names that could leave
that directory, hide a file, or address a Windows device are refused or rewritten.
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse


class UnsafeName(ValueError):
    """The name is not safe to store in the drop directory."""


_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_FORBIDDEN = set('<>:"|?*')
_MAX_LENGTH = 200


def repeated_unquote(value: str, limit: int = 5) -> str:
    current = value
    for _ in range(limit):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def sanitize_filename(raw: str) -> str:
    """Return a single safe path segment or raise UnsafeName."""
    if not isinstance(raw, str) or "\x00" in raw:
        raise UnsafeName("invalid filename")
    name = unicodedata.normalize("NFKC", repeated_unquote(raw)).strip()
    if not name or "\x00" in name:
        raise UnsafeName("invalid filename")
    name = name.replace("\\", "/")
    if "/" in name or name in {".", ".."} or re.match(r"^[A-Za-z]:", name):
        raise UnsafeName("invalid filename")
    name = name.rstrip(" .")
    if not name or name in {".", ".."} or name.startswith("."):
        raise UnsafeName("invalid filename")
    cleaned: list[str] = []
    for char in name:
        if char in _FORBIDDEN or unicodedata.category(char) == "Cf" or not char.isprintable():
            cleaned.append("_")
        else:
            cleaned.append(char)
    name = "".join(cleaned)
    if not name or name in {".", ".."} or name.startswith("."):
        raise UnsafeName("invalid filename")
    stem = name.split(".", 1)[0]
    if stem.upper() in _WINDOWS_RESERVED:
        name = f"{stem}_{name[len(stem) :]}"
    if len(name) > _MAX_LENGTH:
        raise UnsafeName("invalid filename")
    return name


def filename_from_url_path(url_path: str) -> str | None:
    """Return the one file named by an URL path.

    ``/`` is the index and returns None. A nested path or any traversal form
    raises UnsafeName instead of being flattened into the drop directory.
    """
    if not isinstance(url_path, str) or "\x00" in url_path:
        raise UnsafeName("invalid filename")
    decoded = unicodedata.normalize("NFKC", repeated_unquote(url_path))
    if "\x00" in decoded or "\\" in decoded:
        raise UnsafeName("invalid filename")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    if decoded.startswith("//"):
        raise UnsafeName("invalid filename")
    if decoded == "/":
        return None
    rest = decoded[1:]
    if "/" in rest:
        raise UnsafeName("invalid filename")
    return sanitize_filename(rest)
