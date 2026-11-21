"""Shared fixtures for the drop server."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from web_drop.certs import ensure_certificate
from web_drop.server import Config, create_server


@pytest.fixture(autouse=True)
def _clear_password_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_DROP_PASSWORD", raising=False)


class _Drop:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "loot"
        self.root.mkdir()
        self._servers: list[tuple[object, threading.Thread]] = []

    def start(
        self,
        password: str | None = None,
        max_bytes: int = 1024 * 1024,
        https: bool = False,
        log_path: Path | None = None,
        certificate=None,
    ):
        log = log_path or (self.root / ".web-drop" / "transfers.jsonl")
        config = Config(directory=self.root, password=password, max_bytes=max_bytes, log_path=log)
        if certificate is None and https:
            certificate = ensure_certificate(self.tmp / "certs")
        server = create_server("127.0.0.1", 0, config, certificate=certificate)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        thread.start()
        self._servers.append((server, thread))
        return SimpleNamespace(
            port=server.server_address[1],
            root=self.root,
            log=log,
            server=server,
        )

    def close(self) -> None:
        for server, thread in self._servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


@pytest.fixture
def drop(tmp_path: Path) -> _Drop:
    holder = _Drop(tmp_path)
    try:
        yield holder
    finally:
        holder.close()
