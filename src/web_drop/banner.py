"""Startup banner. Small on purpose: the listener lines under it are the useful part."""

from __future__ import annotations

_ART = r"""
            \  |  /
         -- (o)(o) --
          /  /  \  \
         /__/    \__\
            ||  ||
""".strip("\n")


def render_banner(version: str) -> str:
    rule = "      ======================"
    return f"{_ART}\n{rule}\n        web-drop {version}\n        authorized labs only\n{rule}"
