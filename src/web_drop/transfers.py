"""Write uploaded bytes into the drop directory and append the JSONL log."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from web_drop.names import UnsafeName, sanitize_filename


@dataclass(frozen=True)
class SavedFile:
    filename: str
    size: int
    sha256: str
    md5: str


def hash_file(path: Path) -> SavedFile:
    sha256 = hashlib.sha256()
    # MD5 is recorded so it can be compared with certutil -hashfile. SHA-256 is the check to trust.
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
    return SavedFile(path.name, size, sha256.hexdigest(), md5.hexdigest())


def numbered_name(filename: str, index: int) -> str:
    if index == 0:
        return filename
    path = Path(filename)
    return f"{path.stem}-{index}{path.suffix}"


def open_unique(directory: Path, filename: str, reserved: Path | None = None) -> tuple[Path, int]:
    """Create a new file without overwriting anything already in the directory."""
    root = directory.resolve()
    safe = sanitize_filename(filename)
    reserved_path = reserved.resolve() if reserved is not None else None
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for index in range(0, 10001):
        candidate = root / numbered_name(safe, index)
        if candidate.parent.resolve() != root:
            raise UnsafeName("invalid filename")
        if reserved_path is not None and candidate.resolve() == reserved_path:
            continue
        if candidate.is_symlink():
            continue
        try:
            descriptor = os.open(candidate, flags, 0o644)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                continue
            raise
        return candidate, descriptor
    raise UnsafeName("too many files with that name")


def publish(
    directory: Path,
    filename: str,
    source: Path,
    reserved: Path | None = None,
) -> SavedFile:
    hashed = hash_file(source)
    dest, descriptor = open_unique(directory, filename, reserved)
    opened = False
    try:
        output = os.fdopen(descriptor, "wb")
        opened = True
        with output, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, output, length=64 * 1024)
    except Exception:
        if not opened:
            os.close(descriptor)
        dest.unlink(missing_ok=True)
        raise
    return SavedFile(dest.name, hashed.size, hashed.sha256, hashed.md5)


def new_record(
    *,
    source_ip: str,
    method: str,
    direction: str,
    saved: SavedFile,
    status: int,
) -> dict[str, object]:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "direction": direction,
        "filename": saved.filename,
        "size": saved.size,
        "sha256": saved.sha256,
        "md5": saved.md5,
        "status": status,
    }


def format_console(record: dict[str, object]) -> str:
    return (
        f"{record['timestamp']}  {record['direction']}  {record['method']}  "
        f"{record['source_ip']}  {record['filename']}  {record['size']}  "
        f"sha256={record['sha256']}  md5={record['md5']}"
    )


def append_log(log_path: Path, lock: threading.Lock, record: dict[str, object]) -> None:
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with lock:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
        print(format_console(record), flush=True)
