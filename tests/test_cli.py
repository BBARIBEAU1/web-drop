"""The console entry point, banner, and a server started the way a user starts it."""

from __future__ import annotations

import argparse
import os
import re
import select
import signal
import subprocess
import sys
import time
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from tests.helpers import call
from web_drop import __version__
from web_drop.banner import render_banner
from web_drop.cli import main, parse_port, parse_size, run, unauthenticated_warning


def test_banner_names_the_tool_and_the_limit() -> None:
    text = render_banner("0.1.0")
    assert "(o)(o)" in text
    assert "web-drop 0.1.0" in text
    assert "authorized" in text.lower()


def test_help_and_version() -> None:
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0


def test_help_text_lists_both_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    output = capsys.readouterr().out
    assert "serve" in output
    assert "oneliners" in output
    assert "authorized" in output.lower()


def test_size_and_port_parsers() -> None:
    assert parse_size("512M") == 512 * 1024 * 1024
    assert parse_size("1G") == 1024**3
    assert parse_size("2K") == 2048
    assert parse_size("100") == 100
    assert parse_size("1MB") == 1024 * 1024
    with pytest.raises(argparse.ArgumentTypeError):
        parse_size("0")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_size("nope")
    assert parse_port("8000") == 8000
    assert parse_port("0") == 0
    with pytest.raises(argparse.ArgumentTypeError):
        parse_port("70000")


def test_unauthenticated_warning_only_for_a_reachable_bind() -> None:
    assert unauthenticated_warning("0.0.0.0", None)
    assert unauthenticated_warning("127.0.0.1", None) is None
    assert unauthenticated_warning("0.0.0.0", "secret") is None


def test_oneliners_command_uses_flags_and_env(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    sample = tmp_path / "notes.txt"
    sample.write_bytes(b"hello")
    monkeypatch.setenv("WEB_DROP_PASSWORD", "from-env")
    assert run(["oneliners", "--ip", "10.10.14.5", "--file", str(sample)]) == 0
    output = capsys.readouterr().out
    assert "http://10.10.14.5:8000/notes.txt" in output
    assert "token=from-env" in output
    assert "aGVsbG8=" in output

    assert (
        run(["oneliners", "--ip", "10.10.14.5", "--password", "from-flag", "--file", "a.txt"]) == 0
    )
    flagged = capsys.readouterr().out
    assert "token=from-flag" in flagged
    assert "from-env" not in flagged


def test_oneliners_reject_bad_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["oneliners", "--ip", "nope"]) == 2
    assert "invalid ip" in capsys.readouterr().err
    assert run(["oneliners", "--ip", "10.0.0.1", "--file", "../secret"]) == 2
    assert run(["serve", "--password", ""]) == 2


def test_package_version_and_console_script() -> None:
    assert __version__ == "0.1.0"
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.1.0"' in project
    selected = entry_points().select(group="console_scripts")
    match = [item for item in selected if item.name == "web-drop"]
    assert match
    assert match[0].value == "web_drop.cli:main"


def _start_cli(args: list[str], directory: Path, extra_env: dict[str, str] | None = None):
    env = os.environ.copy()
    env.pop("WEB_DROP_PASSWORD", None)
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(root / "src")
    env["PYTHONUNBUFFERED"] = "1"
    if extra_env:
        env.update(extra_env)
    process = subprocess.Popen(
        [sys.executable, "-m", "web_drop", *args],
        cwd=directory,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    return process


def _read_until(process: subprocess.Popen[bytes], needle: bytes, timeout: float = 10) -> str:
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    buffer = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _unused, _errors = select.select([descriptor], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(descriptor, 4096)
            except BlockingIOError:
                chunk = b""
            if not chunk and process.poll() is not None:
                break
            buffer += chunk
            if needle in buffer:
                return buffer.decode()
        elif process.poll() is not None:
            break
    raise AssertionError(buffer.decode(errors="replace"))


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def test_serve_prints_the_banner_and_accepts_a_put(tmp_path: Path) -> None:
    loot = tmp_path / "loot"
    process = _start_cli(
        ["serve", "--bind", "127.0.0.1", "--port", "0", "--dir", str(loot)],
        tmp_path,
    )
    try:
        output = _read_until(process, b"listening on http://")
        assert "(o)(o)" in output
        assert "authorized" in output.lower()
        port = int(re.search(r"listening on http://127\.0\.0\.1:(\d+)", output).group(1))
        status, _body, _headers = call(port, "PUT", "/from-cli.txt", b"cli")
        assert status == 201
        assert (loot / "from-cli.txt").read_bytes() == b"cli"
    finally:
        _stop(process)


def test_no_banner_https_serve(tmp_path: Path) -> None:
    loot = tmp_path / "loot"
    process = _start_cli(
        [
            "serve",
            "--no-banner",
            "--https",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--dir",
            str(loot),
        ],
        tmp_path,
        {"XDG_DATA_HOME": str(tmp_path / "xdg")},
    )
    try:
        output = _read_until(process, b"self-signed")
        assert "listening on https://" in output
        assert "(o)(o)" not in output
        port = int(re.search(r"listening on https://127\.0\.0\.1:(\d+)", output).group(1))
        status, _body, _headers = call(port, "PUT", "/secure.txt", b"tls", https=True)
        assert status == 201
        assert (loot / "secure.txt").read_bytes() == b"tls"
    finally:
        _stop(process)
