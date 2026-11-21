"""Filename sanitizing is the path-traversal boundary."""

from __future__ import annotations

import pytest

from web_drop.names import UnsafeName, filename_from_url_path, sanitize_filename


def test_plain_names_pass_through() -> None:
    assert sanitize_filename("notes.txt") == "notes.txt"
    assert sanitize_filename("my notes.txt") == "my notes.txt"
    assert sanitize_filename("café.txt") == "café.txt"
    assert filename_from_url_path("/notes.txt") == "notes.txt"
    assert filename_from_url_path("/") is None


@pytest.mark.parametrize(
    "raw",
    [
        "../etc/passwd",
        "..\\..\\windows\\win.ini",
        "/etc/passwd",
        "foo/../../etc/passwd",
        "..",
        ".",
        ".bashrc",
        "a\x00b",
        "C:windows",
        "a/\uff0f../passwd",
        "%2e%2e/%2e%2e/etc/passwd",
        "%252e%252e%252fetc/passwd",
    ],
)
def test_sanitize_rejects_traversal_and_hidden_names(raw: str) -> None:
    with pytest.raises(UnsafeName):
        sanitize_filename(raw)


@pytest.mark.parametrize(
    "path",
    [
        "/../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e%252f%252e%252e%252fetc/passwd",
        "/..%5c..%5cwindows%5cwin.ini",
        "/foo/../../secret.txt",
        "//etc/passwd",
        "/a%00b.txt",
        "/.env",
    ],
)
def test_url_paths_that_leave_the_directory_are_rejected(path: str) -> None:
    with pytest.raises(UnsafeName):
        filename_from_url_path(path)


def test_windows_device_names_are_rewritten() -> None:
    assert sanitize_filename("CON.txt") == "CON_.txt"
    assert sanitize_filename("aux") == "aux_"


def test_ntfs_stream_separator_is_replaced() -> None:
    assert sanitize_filename("report.txt:stream") == "report.txt_stream"


def test_fullwidth_slash_cannot_smuggle_a_separator() -> None:
    with pytest.raises(UnsafeName):
        sanitize_filename("a\uff0f..\uff0fpasswd")
