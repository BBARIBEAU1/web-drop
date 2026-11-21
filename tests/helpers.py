"""HTTP helpers shared by the server tests."""

from __future__ import annotations

import http.client
import json
import ssl
from pathlib import Path


def encode_multipart(
    parts: list[tuple[str, str, bytes]],
    boundary: str = "----webdropboundary",
) -> tuple[bytes, str]:
    """Build a multipart body. An empty filename means a plain form field."""
    chunks: list[bytes] = []
    for field, filename, content in parts:
        disposition = f'Content-Disposition: form-data; name="{field}"'
        if filename:
            disposition += f'; filename="{filename}"'
        head = f"--{boundary}\r\n{disposition}\r\n"
        if filename:
            head += "Content-Type: application/octet-stream\r\n"
        head += "\r\n"
        chunks.append(head.encode("utf-8"))
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    body = b"".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


def call(
    port: int,
    method: str,
    target: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    https: bool = False,
) -> tuple[int, bytes, dict[str, str]]:
    if https:
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            "127.0.0.1",
            port,
            context=ssl._create_unverified_context(),
            timeout=5,
        )
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, target, body=body, headers={} if headers is None else headers)
    response = connection.getresponse()
    payload = response.read()
    status = response.status
    found = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return status, payload, found


def read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def basic(user: str, password: str) -> dict[str, str]:
    import base64

    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}
