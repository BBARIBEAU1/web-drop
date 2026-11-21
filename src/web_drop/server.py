"""HTTP server: directory listing, downloads, and POST/PUT uploads."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import shutil
import ssl
import threading
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from web_drop import __version__
from web_drop.certs import Certificate
from web_drop.multipart import UploadRejected, extract_file_parts
from web_drop.names import UnsafeName, filename_from_url_path, sanitize_filename
from web_drop.transfers import SavedFile, append_log, hash_file, new_record, publish

MULTIPART_SLOP = 1024 * 1024

_INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>web-drop</title>
<style>
  :root { color-scheme: dark; }
  body {
    margin: 2.5rem auto;
    max-width: 46rem;
    padding: 0 1.25rem 3rem;
    background: #14120e;
    color: #e7e0d2;
    font: 16px/1.5 Palatino, "Palatino Linotype", serif;
  }
  pre.mark {
    margin: 0 0 0.75rem;
    color: #c9853a;
    font: 13px/1.15 ui-monospace, Menlo, Consolas, monospace;
  }
  h1 { font-size: 1.6rem; font-weight: 600; margin: 0; }
  p.note { color: #a39886; margin: 0.4rem 0 0; }
  form { display: flex; gap: 0.6rem; align-items: center; margin: 1.25rem 0 1.5rem; }
  input, button { font: inherit; color: inherit; }
  button {
    background: #c9853a;
    color: #1a140c;
    border: 0;
    padding: 0.35rem 0.8rem;
    cursor: pointer;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 0.4rem 0.3rem; border-bottom: 1px solid #2c291f; }
  th { color: #a39886; font-weight: 500; }
  a { color: #e0a45a; }
</style>
</head>
<body>
<header>
<pre class="mark">  \\ | /
-- (o) --
 / / \\ \\</pre>
<h1>web-drop</h1>
<p class="note">Authorized labs only. An upload never replaces an existing file.</p>
</header>
<form method="post" enctype="multipart/form-data" action="@@ACTION@@">
  <input type="file" name="file" required>
  <button type="submit">Upload</button>
</form>
<table>
<thead><tr><th>File</th><th>Size</th></tr></thead>
<tbody>
@@ROWS@@
</tbody>
</table>
</body>
</html>
"""


@dataclass
class Config:
    directory: Path
    password: str | None
    max_bytes: int
    log_path: Path
    lock: threading.Lock = field(default_factory=threading.Lock)


class DropServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(size)} B"


def render_index(files: list[tuple[str, int]], *, token: str | None) -> bytes:
    def file_url(name: str) -> str:
        url = "/" + urllib.parse.quote(name, safe="")
        if token:
            url += "?token=" + urllib.parse.quote(token, safe="")
        return html.escape(url, quote=True)

    action = "/"
    if token:
        action += "?token=" + urllib.parse.quote(token, safe="")
    if files:
        rows = []
        for name, size in files:
            label = html.escape(name)
            rows.append(
                "<tr>"
                f'<td><a href="{file_url(name)}">{label}</a></td>'
                f"<td>{html.escape(format_size(size))}</td>"
                "</tr>"
            )
        body = "\n".join(rows)
    else:
        body = '<tr><td colspan="2">No files yet.</td></tr>'
    page = _INDEX_TEMPLATE.replace("@@ACTION@@", html.escape(action, quote=True))
    page = page.replace("@@ROWS@@", body)
    return page.encode("utf-8")


def create_server(
    bind: str,
    port: int,
    config: Config,
    *,
    certificate: Certificate | None = None,
) -> DropServer:
    config.directory.mkdir(parents=True, exist_ok=True)
    config.log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = build_handler(config)
    if certificate is None:
        return DropServer((bind, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate.cert_path, certificate.key_path)

    class TLSServer(DropServer):
        def get_request(self):  # type: ignore[no-untyped-def]
            sock, address = super().get_request()
            try:
                wrapped = context.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                sock.close()
                raise
            return wrapped, address

    return TLSServer((bind, port), handler)


def build_handler(config: Config) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"web-drop/{__version__}"

        def version_string(self) -> str:
            return self.server_version

        def log_message(self, fmt: str, *args) -> None:
            return

        def handle_expect_100(self) -> bool:
            if not check_auth(self, config.password)[0]:
                self._unauthorized()
                return False
            if self.command in {"POST", "PUT"}:
                try:
                    length = declared_length(self.headers)
                except UploadRejected as exc:
                    self._text(exc.status, exc.message, close=True)
                    return False
                cap = body_cap(self.headers.get("Content-Type"), config.max_bytes)
                if length > cap:
                    self._text(413, "upload exceeds max size", close=True)
                    return False
            self.send_response_only(HTTPStatus.CONTINUE)
            self.end_headers()
            return True

        def do_GET(self) -> None:
            self._get()

        def do_POST(self) -> None:
            self._upload()

        def do_PUT(self) -> None:
            self._upload()

        def do_DELETE(self) -> None:
            self._text(405, "method not allowed", extra=[("Allow", "GET, POST, PUT")])

        def _get(self) -> None:
            allowed, token = check_auth(self, config.password)
            if not allowed:
                self._unauthorized()
                return
            try:
                name = filename_from_url_path(urllib.parse.urlsplit(self.path).path)
            except UnsafeName:
                self._reject_name()
                return
            if name is None:
                page = render_index(visible_files(config), token=token)
                self._bytes(HTTPStatus.OK, "text/html; charset=utf-8", page)
                return
            self._download(name)

        def _download(self, name: str) -> None:
            try:
                path = download_path(config, name)
            except UnsafeName:
                self._reject_name()
                return
            except FileNotFoundError:
                self._text(404, "not found")
                return
            saved = hash_file(path)
            payload_size = saved.size
            # Logged before the body is written so a client that has the response
            # can already read the digest from disk.
            self._log("download", saved, HTTPStatus.OK)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(payload_size))
            self.send_header("Content-Disposition", content_disposition(path.name))
            self._security_headers()
            self.end_headers()
            try:
                with path.open("rb") as handle:
                    shutil.copyfileobj(handle, self.wfile, length=64 * 1024)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def _upload(self) -> None:
            allowed, _token = check_auth(self, config.password)
            if not allowed:
                self._unauthorized()
                return
            try:
                url_name = filename_from_url_path(urllib.parse.urlsplit(self.path).path)
            except UnsafeName:
                self._reject_name()
                return
            if self.command == "PUT" and url_name is None:
                self._text(400, "filename required in the URL path", close=True)
                return
            try:
                length = declared_length(self.headers)
            except UploadRejected as exc:
                self._text(exc.status, exc.message, close=True)
                return
            content_type = self.headers.get("Content-Type", "")
            if length > body_cap(content_type, config.max_bytes):
                self._text(413, "upload exceeds max size", close=True)
                return
            incoming = config.directory / ".web-drop" / "incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            spool = incoming / f"{uuid.uuid4().hex}.body"
            part_paths: list[Path] = []
            saved_files: list[SavedFile] | None = None
            try:
                read_exact(self.rfile, length, spool)
                saved_files = self._store(spool, content_type, url_name, incoming, part_paths)
            except UploadRejected as exc:
                self._text(exc.status, exc.message, close=True)
                return
            except UnsafeName:
                self._reject_name()
                return
            except OSError:
                self._text(500, "failed to store upload", close=True)
                return
            finally:
                spool.unlink(missing_ok=True)
                for part in part_paths:
                    part.unlink(missing_ok=True)
            if not saved_files:
                self._text(400, "no file in upload", close=True)
                return
            for item in saved_files:
                self._log("upload", item, HTTPStatus.CREATED)
            encoded = json.dumps({"saved": [asdict(item) for item in saved_files]}, indent=2)
            body = (encoded + "\n").encode()
            self._bytes(HTTPStatus.CREATED, "application/json; charset=utf-8", body)

        def _store(
            self,
            spool: Path,
            content_type: str,
            url_name: str | None,
            incoming: Path,
            part_paths: list[Path],
        ) -> list[SavedFile]:
            if is_multipart(content_type):
                extracted = extract_file_parts(spool, content_type, incoming, config.max_bytes)
                part_paths.extend(path for _name, path in extracted)
                safe_names = [sanitize_filename(name) for name, _path in extracted]
                published: list[SavedFile] = []
                try:
                    pairs = zip(safe_names, extracted, strict=True)
                    for safe, (_raw, path) in pairs:
                        published.append(publish(config.directory, safe, path, config.log_path))
                except Exception:
                    for item in published:
                        (config.directory / item.filename).unlink(missing_ok=True)
                    raise
                return published
            return [publish(config.directory, self._raw_filename(url_name), spool, config.log_path)]

        def _raw_filename(self, url_name: str | None) -> str:
            if url_name:
                return url_name
            header_name = self.headers.get("X-Filename")
            if header_name:
                return sanitize_filename(header_name)
            from_query = query_values(self.path, "filename")
            if from_query:
                return sanitize_filename(from_query[-1])
            return "upload.bin"

        def _log(self, direction: str, saved: SavedFile, status: HTTPStatus) -> None:
            record = new_record(
                source_ip=self.client_address[0],
                method=self.command,
                direction=direction,
                saved=saved,
                status=int(status),
            )
            try:
                append_log(config.log_path, config.lock, record)
            except OSError as exc:
                print(f"failed to write transfer log: {exc}", flush=True)

        def _reject_name(self) -> None:
            print(f"rejected filename from {self.client_address[0]}", flush=True)
            self._text(400, "invalid filename", close=True)

        def _unauthorized(self) -> None:
            print(f"auth failed from {self.client_address[0]}", flush=True)
            self._text(
                401,
                "authentication required",
                extra=[("WWW-Authenticate", 'Basic realm="web-drop"')],
                close=True,
            )

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")

        def _bytes(self, status: HTTPStatus, content_type: str, payload: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(payload)

        def _text(
            self,
            status: int,
            message: str,
            *,
            extra: list[tuple[str, str]] | None = None,
            close: bool = False,
        ) -> None:
            body = (message.rstrip("\n") + "\n").encode("utf-8")
            if close:
                self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            if close:
                self.send_header("Connection", "close")
            if extra:
                for key, value in extra:
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

    return Handler


def visible_files(config: Config) -> list[tuple[str, int]]:
    root = config.directory.resolve()
    log_path = config.log_path.resolve()
    found: list[tuple[str, int]] = []
    if not root.is_dir():
        return found
    for entry in root.iterdir():
        if entry.name.startswith(".") or entry.is_symlink() or not entry.is_file():
            continue
        try:
            resolved = entry.resolve()
        except OSError:
            continue
        if resolved.parent != root or resolved == log_path:
            continue
        found.append((entry.name, resolved.stat().st_size))
    found.sort(key=lambda item: item[0].lower())
    return found


def download_path(config: Config, name: str) -> Path:
    safe = sanitize_filename(name)
    root = config.directory.resolve()
    candidate = root / safe
    if candidate.is_symlink() or not candidate.is_file():
        raise FileNotFoundError(safe)
    resolved = candidate.resolve()
    if resolved.parent != root or resolved == config.log_path.resolve():
        raise FileNotFoundError(safe)
    return candidate


def declared_length(headers) -> int:
    raw = headers.get("Content-Length")
    if raw is None:
        raise UploadRejected(411, "length required")
    text = raw.strip()
    if not text.isdigit():
        raise UploadRejected(400, "bad content length")
    return int(text)


def body_cap(content_type: str | None, max_bytes: int) -> int:
    if is_multipart(content_type or ""):
        return max_bytes + MULTIPART_SLOP
    return max_bytes


def is_multipart(content_type: str) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() == "multipart/form-data"


def read_exact(stream, length: int, dest: Path) -> None:
    remaining = length
    with dest.open("wb") as handle:
        while remaining:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                raise UploadRejected(400, "truncated body")
            handle.write(chunk)
            remaining -= len(chunk)


def content_disposition(filename: str) -> str:
    cleaned = filename.replace("\\", "").replace('"', "")
    return f'attachment; filename="{cleaned}"'


def query_values(path: str, key: str) -> list[str]:
    pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query, keep_blank_values=True)
    return [value for name, value in pairs if name == key]


def passwords_match(provided: str, expected: str) -> bool:
    try:
        left = hashlib.sha256(provided.encode("utf-8")).digest()
        right = hashlib.sha256(expected.encode("utf-8")).digest()
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(left, right)


def basic_password(header: str) -> str | None:
    scheme, _, rest = header.partition(" ")
    if scheme.lower() != "basic" or not rest.strip():
        return None
    try:
        raw = base64.b64decode(rest.strip(), validate=True)
    except (ValueError, binascii.Error):
        return None
    _user, separator, password = raw.partition(b":")
    if not separator:
        return None
    try:
        return password.decode("utf-8")
    except UnicodeDecodeError:
        return None


def check_auth(handler: BaseHTTPRequestHandler, password: str | None) -> tuple[bool, str | None]:
    if not password:
        return True, None
    matched = False
    query_token: str | None = None
    for token in query_values(handler.path, "token"):
        if passwords_match(token, password):
            matched = True
            query_token = token
    header_token = handler.headers.get("X-WebDrop-Token")
    if header_token and passwords_match(header_token, password):
        matched = True
    authorization = handler.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        bearer = authorization.split(None, 1)[1].strip()
        if passwords_match(bearer, password):
            matched = True
    if authorization:
        basic = basic_password(authorization)
        if basic is not None and passwords_match(basic, password):
            matched = True
    if not matched:
        return False, None
    return True, query_token
