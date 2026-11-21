"""HTTPS certificates come from openssl, or from the pure-Python fallback."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests.helpers import call
from web_drop.certs import ensure_certificate


def test_openssl_certificate_loads_and_is_reused(tmp_path) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    cert_dir = tmp_path / "openssl-certs"
    first = ensure_certificate(cert_dir)
    assert first.source == "openssl"
    assert first.warning is None
    assert first.key_path.stat().st_mode & 0o777 == 0o600
    second = ensure_certificate(cert_dir)
    assert second.source == "existing"
    assert second.cert_path.read_bytes() == first.cert_path.read_bytes()
    subject = subprocess.run(
        ["openssl", "x509", "-in", str(first.cert_path), "-noout", "-subject"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "web-drop" in subject.stdout


def test_python_fallback_serves_https(drop, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("web_drop.certs.shutil.which", lambda _name: None)
    certificate = ensure_certificate(drop.tmp / "python-certs")
    assert certificate.source == "python"
    assert certificate.warning is not None
    assert "pure Python" in certificate.warning
    assert certificate.key_path.stat().st_mode & 0o777 == 0o600
    running = drop.start(certificate=certificate)
    status, _body, _headers = call(running.port, "PUT", "/a.txt", b"abc", https=True)
    assert status == 201
    assert (running.root / "a.txt").read_bytes() == b"abc"
