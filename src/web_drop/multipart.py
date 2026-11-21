"""Read file parts out of a multipart/form-data body stored on disk."""

from __future__ import annotations

import os
from email import message_from_bytes
from pathlib import Path


class UploadRejected(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(message)


def _content_type_boundary(content_type: str) -> bytes:
    head, separator, params = content_type.partition(";")
    if not separator or head.strip().lower() != "multipart/form-data":
        raise UploadRejected(400, "expected multipart form data")
    boundary = None
    for param in params.split(";"):
        key, found, value = param.strip().partition("=")
        if found and key.lower() == "boundary":
            boundary = value.strip()
            break
    if not boundary:
        raise UploadRejected(400, "missing multipart boundary")
    if len(boundary) >= 2 and boundary[0] == boundary[-1] and boundary[0] in "\"'":
        boundary = boundary[1:-1]
    if not boundary or len(boundary) > 200:
        raise UploadRejected(400, "invalid multipart boundary")
    try:
        return boundary.encode("ascii")
    except UnicodeEncodeError as exc:
        raise UploadRejected(400, "invalid multipart boundary") from exc


def _read_line(handle, limit: int = 64 * 1024) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        piece = handle.read(1)
        if not piece:
            break
        buf += piece
        if piece == b"\n":
            break
    if len(buf) >= limit and not buf.endswith(b"\n"):
        raise UploadRejected(400, "multipart line too long")
    return bytes(buf)


def _copy_until(handle, marker: bytes, dest, max_file: int) -> None:
    overlap = len(marker) - 1
    pending = b""
    written = 0
    while True:
        chunk = handle.read(64 * 1024)
        pending += chunk
        index = pending.find(marker)
        if index >= 0:
            data = pending[:index]
            if written + len(data) > max_file:
                raise UploadRejected(413, "upload exceeds max size")
            if data:
                dest.write(data)
            extra = pending[index + len(marker) :]
            if extra:
                handle.seek(-len(extra), os.SEEK_CUR)
            return
        if not chunk:
            raise UploadRejected(400, "truncated multipart body")
        if len(pending) > overlap:
            data = pending[:-overlap] if overlap else pending
            pending = pending[-overlap:] if overlap else b""
            if written + len(data) > max_file:
                raise UploadRejected(413, "upload exceeds max size")
            if data:
                dest.write(data)
                written += len(data)


def extract_file_parts(
    body_path: Path,
    content_type: str,
    tmp_dir: Path,
    max_file: int,
) -> list[tuple[str, Path]]:
    """Return ``(filename, path)`` for every file part. Raises UploadRejected."""
    boundary = _content_type_boundary(content_type)
    delimiter = b"--" + boundary
    marker = b"\r\n--" + boundary
    saved: list[tuple[str, Path]] = []
    try:
        with body_path.open("rb") as handle:
            preamble = 0
            while True:
                line = _read_line(handle)
                if not line:
                    raise UploadRejected(400, "missing multipart boundary")
                preamble += len(line)
                if preamble > 64 * 1024:
                    raise UploadRejected(400, "multipart preamble too large")
                if line.rstrip(b"\r\n") == delimiter:
                    break
            seen = 0
            while True:
                seen += 1
                if seen > 100:
                    raise UploadRejected(400, "too many form fields")
                header_blob = bytearray()
                while True:
                    line = _read_line(handle)
                    if not line:
                        raise UploadRejected(400, "truncated multipart headers")
                    header_blob += line
                    if len(header_blob) > 64 * 1024:
                        raise UploadRejected(400, "multipart headers too large")
                    if line in (b"\r\n", b"\n"):
                        break
                message = message_from_bytes(bytes(header_blob))
                filename = message.get_filename()
                if filename:
                    part_path = tmp_dir / f"part-{len(saved)}.bin"
                    try:
                        with part_path.open("wb") as dest:
                            _copy_until(handle, marker, dest, max_file)
                    except Exception:
                        part_path.unlink(missing_ok=True)
                        raise
                    saved.append((filename, part_path))
                else:
                    discard = tmp_dir / "discard.bin"
                    with discard.open("wb") as dest:
                        _copy_until(handle, marker, dest, max_file)
                    discard.unlink(missing_ok=True)
                nxt = handle.read(2)
                if nxt.startswith(b"--"):
                    break
                if nxt == b"\r\n":
                    continue
                if nxt.startswith(b"\n"):
                    if len(nxt) == 2:
                        handle.seek(-1, os.SEEK_CUR)
                    continue
                raise UploadRejected(400, "malformed multipart body")
    except Exception:
        for _name, path in saved:
            path.unlink(missing_ok=True)
        raise
    if not saved:
        raise UploadRejected(400, "no file in upload")
    return saved
