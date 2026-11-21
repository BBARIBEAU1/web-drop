"""Self-signed certificate for ``web-drop serve --https``.

openssl is used when it is on PATH. Otherwise a certificate is generated in
pure Python. Either way the certificate is untrusted; targets skip verification.
"""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
from dataclasses import dataclass
from pathlib import Path

from web_drop.selfsigned import generate_self_signed


@dataclass(frozen=True)
class Certificate:
    cert_path: Path
    key_path: Path
    source: str
    warning: str | None


def default_cert_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "share"
    return root / "web-drop"


def ensure_certificate(dest: Path) -> Certificate:
    dest.mkdir(parents=True, exist_ok=True)
    cert_path = dest / "cert.pem"
    key_path = dest / "key.pem"
    if _usable(cert_path, key_path):
        return Certificate(cert_path, key_path, "existing", None)
    openssl = shutil.which("openssl")
    if openssl:
        try:
            _openssl_generate(openssl, cert_path, key_path)
            os.chmod(key_path, 0o600)
            if _usable(cert_path, key_path):
                return Certificate(cert_path, key_path, "openssl", None)
        except (OSError, subprocess.SubprocessError):
            pass
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
    certificate, key = generate_self_signed("web-drop")
    cert_path.write_text(certificate, encoding="ascii")
    key_path.write_text(key, encoding="ascii")
    os.chmod(key_path, 0o600)
    warning = (
        "openssl was not available; generated a self-signed certificate in pure Python. "
        "Install openssl to create it with the system TLS library instead."
    )
    return Certificate(cert_path, key_path, "python", warning)


def _openssl_generate(openssl: str, cert_path: Path, key_path: Path) -> None:
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "365",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-subj",
            "/CN=web-drop",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )


def _usable(cert_path: Path, key_path: Path) -> bool:
    if not cert_path.is_file() or not key_path.is_file():
        return False
    if cert_path.stat().st_size == 0 or key_path.stat().st_size == 0:
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
    except (OSError, ssl.SSLError):
        return False
    return True
