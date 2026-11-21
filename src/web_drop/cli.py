"""Command line interface for web-drop."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from web_drop import __version__
from web_drop.banner import render_banner
from web_drop.certs import default_cert_dir, ensure_certificate
from web_drop.names import UnsafeName, sanitize_filename
from web_drop.netinfo import choose_ip, detect_ip, host_for_url
from web_drop.oneliners import load_embed, render_oneliners
from web_drop.server import Config, create_server, format_size

DEFAULT_MAX_BYTES = 512 * 1024 * 1024


def parse_size(value: str) -> int:
    text = value.strip().upper()
    if text.isdigit():
        size = int(text)
    else:
        match = re.fullmatch(r"(\d+)([KMG])B?", text)
        if not match:
            raise argparse.ArgumentTypeError("size must look like 512M, 1G, or 4096")
        number = int(match.group(1))
        unit = match.group(2)
        size = number * {None: 1, "K": 1024, "M": 1024**2, "G": 1024**3}[unit]
    if size <= 0 or size > 1024**4:
        raise argparse.ArgumentTypeError("size must be between 1 byte and 1T")
    return size


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if port < 0 or port > 65535:
        raise argparse.ArgumentTypeError("port must be 0-65535")
    return port


def resolve_password(flag: str | None) -> str | None:
    if flag is None:
        flag = os.environ.get("WEB_DROP_PASSWORD")
        if flag is None:
            return None
    if flag == "":
        raise ValueError("password must not be empty")
    return flag


def unauthenticated_warning(bind: str, password: str | None) -> str | None:
    if password is None and bind not in {"127.0.0.1", "::1", "localhost"}:
        return "no password set; this listener is unauthenticated"
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-drop",
        description="Lab file-transfer server for authorized penetration tests.",
        epilog="Authorized labs only. Do not expose this on a network you are not allowed to test.",
    )
    parser.add_argument("--version", action="version", version=f"web-drop {__version__}")
    parser.add_argument(
        "--no-banner",
        action="store_true",
        dest="no_banner_global",
        help="do not print the startup banner",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="serve a directory for download and upload")
    serve.add_argument(
        "--port",
        type=parse_port,
        default=8000,
        help="listen port; 0 picks a free port",
    )
    serve.add_argument("--dir", default="./loot", help="directory to serve (default: ./loot)")
    serve.add_argument("--bind", default="0.0.0.0", help="address to bind (default: 0.0.0.0)")
    serve.add_argument("--https", action="store_true", help="HTTPS with a self-signed certificate")
    serve.add_argument(
        "--password",
        default=None,
        help="require this password (overrides WEB_DROP_PASSWORD)",
    )
    serve.add_argument(
        "--max-size",
        type=parse_size,
        default=DEFAULT_MAX_BYTES,
        help="max upload size, for example 512M or 2G (default: 512M)",
    )
    serve.add_argument(
        "--log",
        default=None,
        help="JSONL log path (default: DIR/.web-drop/transfers.jsonl)",
    )
    serve.add_argument(
        "--no-banner",
        action="store_true",
        dest="no_banner_serve",
        help="do not print the startup banner",
    )

    oneliners = commands.add_parser("oneliners", help="print download and upload commands")
    oneliners.add_argument("--ip", default="auto", help="address to embed, or auto (default: auto)")
    oneliners.add_argument(
        "--port",
        type=parse_port,
        default=8000,
        help="port to embed (default: 8000)",
    )
    oneliners.add_argument("--https", action="store_true", help="print https:// commands")
    oneliners.add_argument(
        "--file",
        default="file.bin",
        help="file name to embed (default: file.bin)",
    )
    oneliners.add_argument(
        "--password",
        default=None,
        help="password to embed as a query token (overrides WEB_DROP_PASSWORD)",
    )
    return parser


def banner_suppressed(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "no_banner_global", False) or getattr(args, "no_banner_serve", False))


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        password = resolve_password(args.password)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    directory = Path(args.dir).expanduser().resolve()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"cannot create {directory}: {exc}", file=sys.stderr)
        return 1
    if args.log:
        log_path = Path(args.log).expanduser().resolve()
    else:
        log_path = directory / ".web-drop" / "transfers.jsonl"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"cannot create log directory: {exc}", file=sys.stderr)
        return 1
    if banner_suppressed(args):
        print(f"web-drop {__version__}", flush=True)
    else:
        print(render_banner(__version__), flush=True)
    config = Config(
        directory=directory,
        password=password,
        max_bytes=args.max_size,
        log_path=log_path,
    )
    certificate = ensure_certificate(default_cert_dir()) if args.https else None
    try:
        server = create_server(args.bind, args.port, config, certificate=certificate)
    except OSError as exc:
        print(f"cannot bind {args.bind}:{args.port}: {exc}", file=sys.stderr)
        return 1
    host, port = server.server_address[:2]
    scheme = "https" if certificate is not None else "http"
    print(f"listening on {scheme}://{host}:{port}", flush=True)
    print(f"root {directory}", flush=True)
    print(f"log {log_path}", flush=True)
    print(f"max upload {format_size(config.max_bytes)}", flush=True)
    if certificate is not None:
        print(f"certificate {certificate.cert_path}", flush=True)
        print("warning: self-signed certificate; targets must skip verification", flush=True)
        if certificate.warning:
            print(f"warning: {certificate.warning}", flush=True)
    warning = unauthenticated_warning(args.bind, password)
    if warning:
        print(f"warning: {warning}", flush=True)
    elif password is not None:
        print("auth: basic, bearer, X-WebDrop-Token, or ?token=", flush=True)
    if args.bind in {"0.0.0.0", "::", ""}:
        ip, source = detect_ip()
        reachable = f"{scheme}://{host_for_url(ip)}:{port}"
        print(f"reachable at {reachable} ({source})", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    finally:
        server.server_close()
    return 0


def cmd_oneliners(args: argparse.Namespace) -> int:
    if args.port == 0:
        print("port must be 1-65535", file=sys.stderr)
        return 2
    try:
        password = resolve_password(args.password)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.ip == "auto":
        ip, source = detect_ip()
    else:
        try:
            ip, source = choose_ip(args.ip, tun0=None, primary=None)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
    path = Path(args.file).expanduser()
    embed = None
    skipped = False
    try:
        if path.is_file():
            filename, embed, skipped = load_embed(path)
        else:
            filename = sanitize_filename(args.file)
    except UnsafeName:
        print("invalid file name", file=sys.stderr)
        return 2
    print(
        render_oneliners(
            ip=ip,
            port=args.port,
            https=args.https,
            filename=filename,
            password=password,
            ip_source=source,
            embed=embed,
            embed_skipped=skipped,
        ),
        end="",
        flush=True,
    )
    return 0


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "oneliners":
        return cmd_oneliners(args)
    parser.error("a command is required")
    return 2


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))
