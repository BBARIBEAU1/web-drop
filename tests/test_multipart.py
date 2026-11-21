"""Multipart bodies have to survive CRLF and a decoy boundary prefix."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import encode_multipart
from web_drop.multipart import UploadRejected, extract_file_parts


def test_file_bytes_including_crlf_are_preserved(tmp_path: Path) -> None:
    content = b"hello\r\n--not-the-boundary\r\nworld"
    body, content_type = encode_multipart(
        [
            ("note", "", b"ignore me"),
            ("file", "notes.txt", content),
        ]
    )
    spool = tmp_path / "body"
    spool.write_bytes(body)
    parts = extract_file_parts(spool, content_type, tmp_path, max_file=1024)
    assert len(parts) == 1
    assert parts[0][0] == "notes.txt"
    assert parts[0][1].read_bytes() == content


def test_two_files_and_an_rfc5987_name(tmp_path: Path) -> None:
    body = (
        b"--bound\r\n"
        b'Content-Disposition: form-data; name="file"; filename="one.txt"\r\n'
        b"\r\n"
        b"one\r\n"
        b"--bound\r\n"
        b"Content-Disposition: form-data; name=\"other\"; filename*=UTF-8''caf%C3%A9.txt\r\n"
        b"\r\n"
        b"caf\xc3\xa9\r\n"
        b"--bound--\r\n"
    )
    spool = tmp_path / "body"
    spool.write_bytes(body)
    parts = extract_file_parts(spool, "multipart/form-data; boundary=bound", tmp_path, 1024)
    assert [name for name, _path in parts] == ["one.txt", "café.txt"]
    assert parts[0][1].read_bytes() == b"one"
    assert parts[1][1].read_bytes() == "café".encode()


def test_text_field_alone_is_rejected(tmp_path: Path) -> None:
    body, content_type = encode_multipart([("note", "", b"hello")])
    spool = tmp_path / "body"
    spool.write_bytes(body)
    with pytest.raises(UploadRejected) as caught:
        extract_file_parts(spool, content_type, tmp_path, 1024)
    assert caught.value.status == 400


def test_part_larger_than_the_cap_is_rejected(tmp_path: Path) -> None:
    body, content_type = encode_multipart([("file", "big.bin", b"0123456789")])
    spool = tmp_path / "body"
    spool.write_bytes(body)
    with pytest.raises(UploadRejected) as caught:
        extract_file_parts(spool, content_type, tmp_path, max_file=4)
    assert caught.value.status == 413
    assert list(tmp_path.glob("part-*")) == []
