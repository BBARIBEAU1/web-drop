"""Uploads, downloads, auth, and the refusal to leave the drop directory."""

from __future__ import annotations

import hashlib
import http.client
import json
import shutil
import subprocess
import urllib.parse
from datetime import datetime

import pytest

from tests.helpers import basic, call, encode_multipart, read_log


def test_put_and_get_round_trip_and_log_hashes(drop) -> None:
    running = drop.start()
    payload = bytes(range(256))
    status, body, _headers = call(running.port, "PUT", "/notes.txt", payload)
    assert status == 201
    saved = json.loads(body)["saved"][0]
    assert saved["filename"] == "notes.txt"
    assert (running.root / "notes.txt").read_bytes() == payload

    status, downloaded, headers = call(running.port, "GET", "/notes.txt")
    assert status == 200
    assert downloaded == payload
    assert headers["content-type"].startswith("application/octet-stream")
    assert 'filename="notes.txt"' in headers["content-disposition"]

    digest_sha = hashlib.sha256(payload).hexdigest()
    digest_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
    entries = read_log(running.log)
    assert [entry["direction"] for entry in entries] == ["upload", "download"]
    for entry in entries:
        assert entry["sha256"] == digest_sha
        assert entry["md5"] == digest_md5
        assert entry["size"] == len(payload)
        assert entry["source_ip"] == "127.0.0.1"
        assert entry["filename"] == "notes.txt"
        datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
    assert entries[0]["method"] == "PUT"
    assert entries[1]["method"] == "GET"


def test_post_raw_body_names(drop) -> None:
    running = drop.start()
    status, _body, _headers = call(running.port, "POST", "/from-url.txt", b"url")
    assert status == 201
    status, _body, _headers = call(
        running.port,
        "POST",
        "/",
        b"header",
        headers={"X-Filename": "from-header.txt"},
    )
    assert status == 201
    status, _body, _headers = call(running.port, "POST", "/?filename=from-query.txt", b"query")
    assert status == 201
    status, _body, _headers = call(running.port, "POST", "/", b"default-one")
    assert status == 201
    status, _body, _headers = call(running.port, "POST", "/", b"default-two")
    assert status == 201
    assert (running.root / "from-url.txt").read_bytes() == b"url"
    assert (running.root / "from-header.txt").read_bytes() == b"header"
    assert (running.root / "from-query.txt").read_bytes() == b"query"
    assert (running.root / "upload.bin").read_bytes() == b"default-one"
    assert (running.root / "upload-1.bin").read_bytes() == b"default-two"


def test_put_to_the_root_requires_a_filename(drop) -> None:
    running = drop.start()
    status, body, _headers = call(running.port, "PUT", "/", b"abc")
    assert status == 400
    assert b"filename required" in body
    stored = [path for path in running.root.rglob("*") if path.is_file()]
    assert stored == []


def test_multipart_post_keeps_file_bytes(drop) -> None:
    running = drop.start()
    content = b"hello\r\nworld"
    body, content_type = encode_multipart(
        [("note", "", b"ignore"), ("upload", "notes.txt", content)]
    )
    status, response, _headers = call(
        running.port,
        "POST",
        "/",
        body,
        headers={"Content-Type": content_type},
    )
    assert status == 201
    assert (running.root / "notes.txt").read_bytes() == content
    assert json.loads(response)["saved"][0]["sha256"] == hashlib.sha256(content).hexdigest()


def test_existing_files_are_not_overwritten(drop) -> None:
    running = drop.start()
    assert call(running.port, "PUT", "/archive.tar.gz", b"one")[0] == 201
    assert call(running.port, "PUT", "/archive.tar.gz", b"two")[0] == 201
    assert call(running.port, "PUT", "/archive.tar.gz", b"three")[0] == 201
    assert (running.root / "archive.tar.gz").read_bytes() == b"one"
    assert (running.root / "archive.tar-1.gz").read_bytes() == b"two"
    assert (running.root / "archive.tar-2.gz").read_bytes() == b"three"
    names = [entry["filename"] for entry in read_log(running.log)]
    assert names == ["archive.tar.gz", "archive.tar-1.gz", "archive.tar-2.gz"]


@pytest.mark.parametrize(
    "target",
    [
        "/../../secret.txt",
        "/%2e%2e/%2e%2e/secret.txt",
        "/%252e%252e%252f%252e%252e%252fsecret.txt",
        "/..%5c..%5csecret.txt",
        "/foo/../../secret.txt",
        "/a%00b.txt",
    ],
)
def test_put_path_traversal_is_rejected(drop, target: str) -> None:
    running = drop.start()
    marker = b"pwned-marker"
    status, _body, _headers = call(running.port, "PUT", target, marker)
    assert status == 400
    stored = b"".join(path.read_bytes() for path in running.root.rglob("*") if path.is_file())
    assert marker not in stored
    assert not (drop.tmp / "secret.txt").exists()


def test_multipart_filename_traversal_is_rejected(drop) -> None:
    running = drop.start()
    marker = b"pwned-marker"
    body, content_type = encode_multipart([("file", "../../secret.txt", marker)])
    status, _body, _headers = call(
        running.port,
        "POST",
        "/",
        body,
        headers={"Content-Type": content_type},
    )
    assert status == 400
    stored = b"".join(path.read_bytes() for path in running.root.rglob("*") if path.is_file())
    assert marker not in stored


def test_header_and_query_filenames_cannot_escape(drop) -> None:
    running = drop.start()
    status, _body, _headers = call(
        running.port,
        "POST",
        "/",
        b"x",
        headers={"X-Filename": "..\\..\\secret.txt"},
    )
    assert status == 400
    status, _body, _headers = call(running.port, "POST", "/?filename=../secret.txt", b"x")
    assert status == 400
    assert not (drop.tmp / "secret.txt").exists()


def test_symlink_is_not_served_or_followed_on_upload(drop) -> None:
    running = drop.start()
    secret = drop.tmp / "secret.txt"
    secret.write_text("supersecret", encoding="utf-8")
    link = running.root / "link.txt"
    link.symlink_to(secret)
    status, body, _headers = call(running.port, "GET", "/link.txt")
    assert status == 404
    assert b"supersecret" not in body

    notes = running.root / "notes.txt"
    notes.symlink_to(secret)
    status, _body, _headers = call(running.port, "PUT", "/notes.txt", b"new")
    assert status == 201
    assert secret.read_text(encoding="utf-8") == "supersecret"
    assert (running.root / "notes-1.txt").read_bytes() == b"new"
    assert notes.is_symlink()


def test_listing_escapes_names_and_hides_the_log(drop) -> None:
    running = drop.start()
    assert b"No files yet." in call(running.port, "GET", "/")[1]
    assert call(running.port, "PUT", "/my%20notes.txt", b"abc")[0] == 201
    status, page, headers = call(running.port, "GET", "/")
    assert status == 200
    text = page.decode()
    assert headers["content-type"].startswith("text/html")
    assert "multipart/form-data" in text
    assert 'name="file"' in text
    assert 'href="/my%20notes.txt"' in text
    assert ".web-drop" not in text
    assert "transfers.jsonl" not in text
    status, body, _headers = call(running.port, "GET", "/.web-drop/transfers.jsonl")
    assert status == 400
    assert b"sha256" not in body


def test_index_renderer_escapes_markup() -> None:
    from web_drop.server import render_index

    page = render_index([("a<b>.txt", 3)], token='"><script>').decode()
    assert "a&lt;b&gt;.txt" in page
    assert "a<b>.txt" not in page
    assert "<script>" not in page
    assert "token=%22%3E%3Cscript%3E" in page


def test_auth_blocks_anonymous_reads_and_writes(drop) -> None:
    running = drop.start(password="s3cret")
    (running.root / "notes.txt").write_bytes(b"hidden")
    status, body, headers = call(running.port, "GET", "/")
    assert status == 401
    assert b"notes.txt" not in body
    assert "basic" in headers["www-authenticate"].lower()
    status, _body, _headers = call(running.port, "PUT", "/x.txt", b"nope")
    assert status == 401
    assert not (running.root / "x.txt").exists()


@pytest.mark.parametrize(
    "headers",
    [
        basic("webdrop", "s3cret"),
        basic("anyone", "s3cret"),
        basic("", "s3cret"),
        {"Authorization": "Bearer s3cret"},
        {"Authorization": "bearer s3cret"},
        {"X-WebDrop-Token": "s3cret"},
    ],
)
def test_accepted_credentials(drop, headers: dict[str, str]) -> None:
    running = drop.start(password="s3cret")
    status, _body, _headers = call(running.port, "PUT", "/ok.txt", b"yes", headers=headers)
    assert status == 201
    assert (running.root / "ok.txt").read_bytes() == b"yes"
    (running.root / "ok.txt").unlink()


def test_query_token_works_for_upload_and_download(drop) -> None:
    password = "a&b=c"
    running = drop.start(password=password)
    token = urllib.parse.quote(password, safe="")
    status, _body, _headers = call(running.port, "PUT", f"/notes.txt?token={token}", b"secret")
    assert status == 201
    status, body, _headers = call(running.port, "GET", f"/notes.txt?token={token}")
    assert status == 200
    assert body == b"secret"
    page = call(running.port, "GET", f"/?token={token}")[1].decode()
    assert f"token={token}" in page
    assert "a&b=c" not in page
    wrong = call(running.port, "PUT", "/other.txt?token=nope", b"no")
    assert wrong[0] == 401
    assert not (running.root / "other.txt").exists()


def test_wrong_basic_password_writes_nothing(drop) -> None:
    running = drop.start(password="s3cret")
    status, _body, _headers = call(
        running.port,
        "PUT",
        "/x.txt",
        b"nope",
        headers=basic("webdrop", "wrong"),
    )
    assert status == 401
    assert not (running.root / "x.txt").exists()


def test_max_size_rejects_the_extra_byte_and_keeps_the_exact_fit(drop) -> None:
    running = drop.start(max_bytes=8)
    assert call(running.port, "PUT", "/exact.txt", b"12345678")[0] == 201
    status, body, _headers = call(running.port, "PUT", "/over.txt", b"123456789")
    assert status == 413
    assert b"max size" in body
    assert not (running.root / "over.txt").exists()
    assert (running.root / "exact.txt").read_bytes() == b"12345678"


def test_multipart_max_size_is_the_file_not_the_framing(drop) -> None:
    running = drop.start(max_bytes=8)
    body, content_type = encode_multipart([("file", "big.txt", b"123456789")])
    status, _response, _headers = call(
        running.port,
        "POST",
        "/",
        body,
        headers={"Content-Type": content_type},
    )
    assert status == 413
    assert list(running.root.glob("*.txt")) == []


def test_missing_content_length_is_rejected(drop) -> None:
    running = drop.start()
    connection = http.client.HTTPConnection("127.0.0.1", running.port, timeout=5)
    connection.putrequest("POST", "/notes.txt")
    connection.putheader("Content-Type", "application/octet-stream")
    connection.endheaders()
    response = connection.getresponse()
    assert response.status == 411
    connection.close()


def test_empty_upload_has_the_empty_digests(drop) -> None:
    running = drop.start()
    assert call(running.port, "PUT", "/empty.txt", b"")[0] == 201
    entry = read_log(running.log)[0]
    assert entry["size"] == 0
    assert entry["sha256"] == hashlib.sha256(b"").hexdigest()
    assert entry["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()


def test_delete_is_not_implemented(drop) -> None:
    running = drop.start()
    status, _body, headers = call(running.port, "DELETE", "/notes.txt")
    assert status == 405
    assert "PUT" in headers["allow"]


def test_windows_reserved_and_unicode_names(drop) -> None:
    running = drop.start()
    assert call(running.port, "PUT", "/CON.txt", b"device")[0] == 201
    assert (running.root / "CON_.txt").read_bytes() == b"device"
    assert call(running.port, "PUT", "/caf%C3%A9.txt", "café".encode())[0] == 201
    assert (running.root / "café.txt").read_bytes() == "café".encode()


def test_log_file_inside_the_root_is_not_served_or_overwritten(drop) -> None:
    log_path = drop.root / "transfers.jsonl"
    running = drop.start(log_path=log_path)
    status, _body, _headers = call(running.port, "PUT", "/transfers.jsonl", b"hello")
    assert status == 201
    assert (running.root / "transfers-1.jsonl").read_bytes() == b"hello"
    assert b"hello" not in log_path.read_bytes()
    status, body, _headers = call(running.port, "GET", "/transfers.jsonl")
    assert status == 404
    assert b"hello" not in body
    listing = call(running.port, "GET", "/")[1].decode()
    assert 'href="/transfers.jsonl"' not in listing
    assert "transfers-1.jsonl" in listing


def test_curl_put_and_multipart(drop) -> None:
    if shutil.which("curl") is None:
        pytest.skip("curl is not installed")
    running = drop.start()
    sample = drop.tmp / "sample.txt"
    sample.write_bytes(b"from-curl\r\n")
    base = f"http://127.0.0.1:{running.port}"
    put = subprocess.run(
        [
            "curl",
            "--http1.1",
            "--fail",
            "--silent",
            "--show-error",
            "-T",
            str(sample),
            f"{base}/from-curl.txt",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert put.returncode == 0, put.stderr
    form = subprocess.run(
        [
            "curl",
            "--http1.1",
            "--fail",
            "--silent",
            "--show-error",
            "-F",
            f"file=@{sample}",
            f"{base}/",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert form.returncode == 0, form.stderr
    assert (running.root / "from-curl.txt").read_bytes() == b"from-curl\r\n"
    assert (running.root / "sample.txt").read_bytes() == b"from-curl\r\n"
